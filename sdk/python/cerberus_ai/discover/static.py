"""
Static scanner for :mod:`cerberus_ai.discover`.

Walks a directory tree, parses every ``.py`` file's AST, and emits a
:class:`DiscoveryReport` of LLM call sites + tool registrations. Then
sweeps common MCP-client config locations for server manifests.

The scanner is designed to be zero-dependency (standard library only)
so it can run inside CI, an air-gapped build box, or a developer laptop
without pulling in ONNX / torch / Anthropic / OpenAI client libraries.

Detection strategy per file:

* Parse with :mod:`ast`. If the parse fails, record the error but keep
  scanning — a single broken file must not abort the whole report.
* Walk ``Import`` / ``ImportFrom`` nodes to build a framework map.
* Walk ``Call`` nodes and match them against a fixed set of known
  attribute paths (e.g. ``openai.OpenAI``, ``anthropic.Anthropic``,
  ``langchain_openai.ChatOpenAI``, ``crewai.Agent``, ...).
* If the same file instantiates ``cerberus_ai.Cerberus`` (or
  ``cerberus_ai.cerberus.Cerberus``), mark every call site in that
  file as ``wrapped_by_cerberus=True``. It's a conservative heuristic
  — real coverage requires the wrapper to also be *used*, but the
  static scanner cannot prove runtime coverage.
"""
from __future__ import annotations

import ast
import json
import logging
import os
from pathlib import Path

from cerberus_ai.discover.schema import (
    CallSite,
    DiscoveryReport,
    Framework,
    MCPServer,
)

logger = logging.getLogger("cerberus.discover")

# Files & directories ignored during the static scan. Kept small — we
# want to find AI call sites in tests and examples too, since those are
# often the "I forgot to wrap the staging runner" failure case.
_SKIP_DIRS: frozenset[str] = frozenset({
    ".git", ".hg", ".svn", ".tox", ".venv", "venv", "env",
    "__pycache__", "node_modules", "dist", "build", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", ".cache", "site-packages",
})

# Patterns to recognise. Each entry is (dotted-path, framework, model_family).
# First match wins.
#
# **Invariant:** every pattern must be at most two dotted segments. The
# matcher only permits leaf-name matching for 2-segment patterns (e.g.
# ``openai.OpenAI`` → ``OpenAI(...)`` or ``x.OpenAI(...)``). A 3-segment
# pattern like ``openai.ChatCompletion.create`` would silently match every
# ``.create(...)`` call in user code (``db.objects.create``,
# ``factory.create``, ``client.messages.create``) and misclassify it as
# OpenAI — a bug we deliberately avoid. Detecting the client constructor
# (``OpenAI()`` / ``Anthropic()``) is sufficient and far more reliable.
_CALL_PATTERNS: tuple[tuple[str, Framework, str | None], ...] = (
    # Raw client SDKs — constructors only, not methods.
    ("openai.OpenAI", "openai", "openai"),
    ("openai.AsyncOpenAI", "openai", "openai"),
    ("anthropic.Anthropic", "anthropic", "anthropic"),
    ("anthropic.AsyncAnthropic", "anthropic", "anthropic"),
    ("google.GenerativeModel", "google", "google"),
    ("genai.GenerativeModel", "google", "google"),
    # LangChain / LangGraph
    ("langchain_openai.ChatOpenAI", "langchain", "openai"),
    ("langchain_anthropic.ChatAnthropic", "langchain", "anthropic"),
    ("langchain_google_genai.ChatGoogleGenerativeAI", "langchain", "google"),
    ("langgraph.StateGraph", "langgraph", None),
    # Multi-agent frameworks
    ("crewai.Agent", "crewai", None),
    ("crewai.Crew", "crewai", None),
    ("autogen.ConversableAgent", "autogen", None),
    ("autogen.AssistantAgent", "autogen", None),
    ("autogen.UserProxyAgent", "autogen", None),
    # LlamaIndex — constructors only. Generic-leaf methods like
    # ``.from_documents`` / ``.as_query_engine`` are intentionally NOT
    # patterns because they name-collide with unrelated libraries.
    ("llama_index.RetrieverQueryEngine", "llamaindex", None),
    ("llama_index.AgentRunner", "llamaindex", None),
    ("llama_index.ChatEngine", "llamaindex", None),
    ("llama_index.VectorStoreIndex", "llamaindex", None),
    # MCP client bindings
    ("mcp.stdio_client", "mcp-client", None),
    ("mcp.ClientSession", "mcp-client", None),
)

# Leaves that are too generic to be matched leaf-only without false
# positives (e.g. ``aiohttp.ClientSession`` would otherwise be tagged
# as ``mcp-client``). For these names the matcher requires the dotted
# call target to actually contain the framework module — exact match
# (``mcp.ClientSession``), namespaced match (``mcp.client.ClientSession``),
# or a bare ``ClientSession`` name only when the source file imports it
# from the ``mcp`` package.
_GENERIC_LEAVES: frozenset[str] = frozenset({"ClientSession"})

# Recognised tool-declaration patterns — call sites that appear near
# these are marked with their tool set.
_TOOL_DECL_PATTERNS: tuple[str, ...] = (
    "Tool",
    "StructuredTool.from_function",
    "StructuredTool",
    "tool",  # common `from langchain.tools import tool` decorator name
    "FunctionTool.from_defaults",
    "FunctionTool",
)

# Common paths where MCP clients store server registrations. Paths are
# checked as direct files and as globs (e.g. VS Code extension setups
# that dump one file per workspace).
_MCP_CONFIG_LOCATIONS: tuple[str, ...] = (
    "mcp.json",
    ".cursor/mcp.json",
    ".vscode/mcp.json",
    ".config/Claude/claude_desktop_config.json",
    ".config/claude-desktop/config.json",
    "Library/Application Support/Claude/claude_desktop_config.json",
    "AppData/Roaming/Claude/claude_desktop_config.json",
)


def _dotted_name(node: ast.AST) -> str:
    """Best-effort dotted-path recovery for a Call target.

    ``ast.Attribute`` and ``ast.Name`` are chained into a single
    ``a.b.c`` string. Anything else (subscripts, calls, comprehensions)
    returns ``""``.
    """
    parts: list[str] = []
    cur: ast.AST = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    else:
        return ""
    return ".".join(reversed(parts))


def _match_pattern(
    dotted: str,
    imported_modules: frozenset[str] = frozenset(),
) -> tuple[Framework, str | None] | None:
    """Return ``(framework, model_family)`` for a dotted call target,
    or ``None`` if nothing matches.

    Every pattern in :data:`_CALL_PATTERNS` is exactly two segments
    (``module.ClassName``). The matcher accepts three forms, in order:

    * Exact match against the full pattern.
    * Trailing-segment match on a dotted call
      (``x.OpenAI(...)`` against ``openai.OpenAI``).
    * Bare-name match for ``from pkg import Name`` style imports
      (``OpenAI(...)`` against ``openai.OpenAI``).

    Leaf-only matching is only safe because every leaf is a framework
    class name (``OpenAI``, ``Anthropic``, ``StateGraph``, ...). Adding
    a pattern with a generic leaf like ``.create`` or ``.from_documents``
    would cause spurious matches on unrelated code — the loader asserts
    the two-segment invariant so we can't regress silently.

    For leaves listed in :data:`_GENERIC_LEAVES` (e.g. ``ClientSession``,
    which ``aiohttp`` and ``httpx`` also expose), bare-name and trailing
    matches are gated on ``imported_modules`` actually containing the
    pattern's module. Without that gate, ``aiohttp.ClientSession(...)``
    would be misclassified as ``mcp-client``.
    """
    for pattern, framework, family in _CALL_PATTERNS:
        if dotted == pattern:
            return framework, family
        # Invariant enforced at module load (see _assert_pattern_shape).
        module, leaf = pattern.split(".", 1)
        candidate = (
            dotted == leaf
            or dotted.endswith("." + leaf)
            or dotted.startswith(leaf + ".")
        )
        if not candidate:
            continue
        if leaf in _GENERIC_LEAVES:
            # Generic leaf: require the dotted path to actually be in
            # the framework module, or the source file to have imported
            # the module. Otherwise this is an unrelated library that
            # happens to share the class name (aiohttp.ClientSession).
            in_module = (
                dotted.startswith(module + ".")
                or ("." + module + ".") in "." + dotted + "."
            )
            if not (in_module or module in imported_modules):
                continue
        # ``X.y(...)`` — classmethod / alternate-constructor style
        # (e.g. ``VectorStoreIndex.from_documents(...)``) is routed
        # back to the class's framework. Safe because every leaf is
        # a specific framework class name, not a generic verb.
        return framework, family
    return None


def _assert_pattern_shape() -> None:
    """Guard against regressions that silently broaden the scanner.

    Every entry in :data:`_CALL_PATTERNS` must be exactly two dotted
    segments. A three-segment pattern would leak into the leaf-match
    branch of :func:`_match_pattern` and cause spurious false positives
    — this assertion makes that a fail-fast import error rather than a
    hard-to-debug runtime classification bug.
    """
    for pattern, _framework, _family in _CALL_PATTERNS:
        if pattern.count(".") != 1:
            raise AssertionError(
                f"cerberus_ai.discover._CALL_PATTERNS: pattern {pattern!r} "
                "must be exactly two dotted segments (module.ClassName). "
                "See _match_pattern docstring for rationale."
            )


_assert_pattern_shape()


def _is_cerberus_instantiation(dotted: str) -> bool:
    """True when a call target looks like ``cerberus_ai.Cerberus(...)``.

    The scanner uses this to flag every LLM call site in the same file
    as ``wrapped_by_cerberus=True`` (best-effort static coverage).
    """
    if dotted == "Cerberus":
        return True
    if dotted.endswith(".Cerberus"):
        return True
    return False


def _is_tool_declaration(dotted: str) -> bool:
    """True when a call looks like ``Tool(name="...")`` or similar."""
    if dotted in _TOOL_DECL_PATTERNS:
        return True
    return any(dotted.endswith("." + p) for p in _TOOL_DECL_PATTERNS)


def _extract_tool_name(call: ast.Call) -> str | None:
    """Return the ``name=`` kwarg or first string positional argument
    of a tool-declaration call.
    """
    for kw in call.keywords:
        if kw.arg == "name" and isinstance(kw.value, ast.Constant):
            val = kw.value.value
            if isinstance(val, str):
                return val
    for arg in call.args:
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            return arg.value
    return None


def _scan_python_file(path: Path, root: Path) -> tuple[list[CallSite], list[str]]:
    """Parse ``path`` and return any call sites it contains."""
    call_sites: list[CallSite] = []
    errors: list[str] = []
    try:
        source = path.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        errors.append(f"read {path}: {e}")
        return [], errors
    try:
        tree = ast.parse(source, filename=str(path))
    except SyntaxError as e:
        errors.append(f"parse {path}: {e}")
        return [], errors

    # Pass 0: collect top-level module names imported by this file so
    # generic-leaf patterns (see :data:`_GENERIC_LEAVES`) only match
    # when the corresponding framework was actually imported.
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module:
                imported.add(node.module.split(".", 1)[0])
        elif isinstance(node, ast.Import):
            for alias in node.names:
                imported.add(alias.name.split(".", 1)[0])
    imported_modules = frozenset(imported)

    # Pass 1: decide if the file instantiates Cerberus.
    wrapped_file = False
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            dotted = _dotted_name(node.func)
            if _is_cerberus_instantiation(dotted):
                wrapped_file = True
                break

    # Pass 2: collect tool-name declarations (by line) so we can attach
    # them to nearby call sites.
    tools_in_file: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            dotted = _dotted_name(node.func)
            if _is_tool_declaration(dotted):
                name = _extract_tool_name(node)
                if name:
                    tools_in_file.append(name)

    # Pass 3: emit call sites.
    rel = path.relative_to(root).as_posix() if path.is_relative_to(root) else str(path)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        dotted = _dotted_name(node.func)
        if not dotted:
            continue
        hit = _match_pattern(dotted, imported_modules=imported_modules)
        if hit is None:
            continue
        framework, family = hit
        call_sites.append(CallSite(
            file=rel,
            line=node.lineno,
            framework=framework,
            symbol=dotted.split(".")[-1],
            model_family=family,
            wrapped_by_cerberus=wrapped_file,
            tools_registered=tuple(tools_in_file),
        ))
    return call_sites, errors


def _iter_python_files(root: Path) -> list[Path]:
    """Walk ``root``, yielding every ``.py`` file not in a skipped dir."""
    out: list[Path] = []
    for base, dirs, files in os.walk(root):
        # Prune skip dirs in-place so we don't descend into them.
        dirs[:] = [d for d in dirs if d not in _SKIP_DIRS and not d.startswith(".")]
        for name in files:
            if name.endswith(".py"):
                out.append(Path(base) / name)
    return out


def _parse_mcp_config(path: Path) -> list[MCPServer]:
    """Parse an MCP client config file and return every registered
    server. The format varies — we accept both
    ``{"mcpServers": {"name": {...}}}`` (Claude Desktop, Cursor, VSCode)
    and ``{"servers": [...]}`` (some one-off tools).
    """
    try:
        raw = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError) as e:
        logger.debug("skip mcp config %s: %s", path, e)
        return []
    servers: list[MCPServer] = []
    if isinstance(raw, dict) and isinstance(raw.get("mcpServers"), dict):
        for name, entry in raw["mcpServers"].items():
            if not isinstance(entry, dict):
                continue
            servers.append(MCPServer(
                name=str(name),
                config_path=str(path),
                command=entry.get("command") if isinstance(entry.get("command"), str) else None,
                args=tuple(str(a) for a in entry.get("args", []) if isinstance(a, (str, int))),
                tool_count=None,
            ))
    elif isinstance(raw, dict) and isinstance(raw.get("servers"), list):
        for entry in raw["servers"]:
            if not isinstance(entry, dict):
                continue
            servers.append(MCPServer(
                name=str(entry.get("name", "unknown")),
                config_path=str(path),
                command=entry.get("command") if isinstance(entry.get("command"), str) else None,
                args=tuple(str(a) for a in entry.get("args", []) if isinstance(a, (str, int))),
                tool_count=len(entry.get("tools", []))
                if isinstance(entry.get("tools"), list) else None,
            ))
    return servers


def _find_mcp_configs(root: Path, include_home: bool) -> list[Path]:
    """Enumerate MCP config files under ``root`` and (optionally) the
    user's home directory."""
    found: list[Path] = []
    for rel in _MCP_CONFIG_LOCATIONS:
        p = root / rel
        if p.is_file():
            found.append(p)
    if include_home:
        home = Path.home()
        for rel in _MCP_CONFIG_LOCATIONS:
            p = home / rel
            if p.is_file() and p not in found:
                found.append(p)
    return found


def scan_repo(
    root: str | os.PathLike[str],
    *,
    include_mcp_home: bool = False,
) -> DiscoveryReport:
    """Static-scan ``root`` and return a :class:`DiscoveryReport`.

    Parameters
    ----------
    root:
        Repository root to walk.
    include_mcp_home:
        If ``True``, also inspect the user's home directory for MCP
        client configurations (Claude Desktop, Cursor, VSCode). Off by
        default so the scanner is deterministic on CI.
    """
    rp = Path(root).resolve()
    report = DiscoveryReport.new(str(rp))
    if not rp.exists():
        report.errors.append(f"root does not exist: {rp}")
        return report
    for py in _iter_python_files(rp):
        sites, errors = _scan_python_file(py, rp)
        report.call_sites.extend(sites)
        report.errors.extend(errors)
    for cfg in _find_mcp_configs(rp, include_home=include_mcp_home):
        report.mcp_servers.extend(_parse_mcp_config(cfg))
    return report
