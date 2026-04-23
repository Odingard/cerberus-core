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

# (attribute path matched against the call's dotted name, framework
# label, model_family hint). First match wins.
_CALL_PATTERNS: tuple[tuple[str, Framework, str | None], ...] = (
    # Raw client SDKs
    ("openai.OpenAI", "openai", "openai"),
    ("openai.AsyncOpenAI", "openai", "openai"),
    ("openai.ChatCompletion.create", "openai", "openai"),
    ("OpenAI", "openai", "openai"),
    ("anthropic.Anthropic", "anthropic", "anthropic"),
    ("anthropic.AsyncAnthropic", "anthropic", "anthropic"),
    ("Anthropic", "anthropic", "anthropic"),
    ("anthropic.messages.create", "anthropic", "anthropic"),
    ("google.generativeai.GenerativeModel", "google", "google"),
    ("genai.GenerativeModel", "google", "google"),
    ("GenerativeModel", "google", "google"),
    # LangChain / LangGraph
    ("langchain_openai.ChatOpenAI", "langchain", "openai"),
    ("langchain_anthropic.ChatAnthropic", "langchain", "anthropic"),
    ("langchain_google_genai.ChatGoogleGenerativeAI", "langchain", "google"),
    ("ChatOpenAI", "langchain", "openai"),
    ("ChatAnthropic", "langchain", "anthropic"),
    ("langgraph.graph.StateGraph", "langgraph", None),
    ("StateGraph", "langgraph", None),
    # Multi-agent frameworks
    ("crewai.Agent", "crewai", None),
    ("crewai.Crew", "crewai", None),
    ("Crew", "crewai", None),
    ("autogen.ConversableAgent", "autogen", None),
    ("autogen.AssistantAgent", "autogen", None),
    ("autogen.UserProxyAgent", "autogen", None),
    ("ConversableAgent", "autogen", None),
    ("AssistantAgent", "autogen", None),
    # LlamaIndex
    ("llama_index.core.query_engine.RetrieverQueryEngine",
     "llamaindex", None),
    ("llama_index.core.agent.AgentRunner", "llamaindex", None),
    ("llama_index.core.chat_engine.ChatEngine", "llamaindex", None),
    ("VectorStoreIndex.from_documents", "llamaindex", None),
    # MCP client bindings
    ("mcp.client.stdio.stdio_client", "mcp-client", None),
    ("mcp.ClientSession", "mcp-client", None),
    ("ClientSession", "mcp-client", None),
)

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


def _match_pattern(dotted: str) -> tuple[Framework, str | None] | None:
    """Return ``(framework, model_family)`` for a dotted call target,
    or ``None`` if nothing matches.

    The matcher supports three forms so we stay robust across import
    styles:

    * Exact dotted-path match (``openai.OpenAI`` → ``openai.OpenAI(...)``)
    * Trailing-segment match on a dotted call
      (``x.OpenAI(...)`` against pattern ``openai.OpenAI``)
    * Bare-name match for ``from pkg import Name`` style imports
      (``OpenAI(...)`` against pattern ``openai.OpenAI``)
    """
    for pattern, framework, family in _CALL_PATTERNS:
        if dotted == pattern:
            return framework, family
        if "." in pattern:
            leaf = pattern.rsplit(".", 1)[-1]
            if dotted.endswith("." + leaf) or dotted == leaf:
                return framework, family
    return None


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
        hit = _match_pattern(dotted)
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
