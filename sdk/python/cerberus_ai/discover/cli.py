"""
``cerberus discover`` — static repository scanner.

The console script is registered in ``pyproject.toml`` under
``[project.scripts]``. We implement the CLI with :mod:`argparse` so
the scanner has no third-party runtime dependency.

Usage examples::

    cerberus discover --root ./
    cerberus discover --root /path/to/repo --output discovery.json
    cerberus discover --include-mcp-home --format text
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import TextIO

from cerberus_ai.discover.schema import DiscoveryReport
from cerberus_ai.discover.static import scan_repo


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cerberus",
        description="Cerberus runtime security middleware CLI.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    discover = sub.add_parser(
        "discover",
        help="Statically scan a repo for LLM call sites, tools, and MCP servers.",
    )
    discover.add_argument(
        "--root", "-r", default=".",
        help="Repository root to scan. Defaults to the current directory.",
    )
    discover.add_argument(
        "--output", "-o", default=None,
        help="Write the report to PATH. Defaults to stdout.",
    )
    discover.add_argument(
        "--format", "-f", choices=("json", "text"), default="json",
        help="Output format.",
    )
    discover.add_argument(
        "--include-mcp-home", action="store_true",
        help="Also scan the user's home directory for MCP client configs "
             "(Claude Desktop, Cursor, VSCode). Off by default so CI runs "
             "are deterministic.",
    )
    return parser


def _render_text(report: DiscoveryReport, out: TextIO) -> None:
    """Human-readable report — colour-free for CI log compatibility."""
    cov = report.coverage
    print(f"Cerberus discovery report — {report.scan_id}", file=out)
    print(f"  root: {report.root}", file=out)
    print(f"  generated_at: {report.generated_at}", file=out)
    print("", file=out)
    print(
        f"  call sites: {cov.total_call_sites}  "
        f"(wrapped: {cov.wrapped}, unwrapped: {cov.unwrapped}, "
        f"coverage: {cov.coverage_pct}%)",
        file=out,
    )
    print(f"  mcp servers: {len(report.mcp_servers)}", file=out)
    print(f"  errors: {len(report.errors)}", file=out)
    print("", file=out)
    if report.call_sites:
        print("Call sites:", file=out)
        for c in report.call_sites:
            wrapped = "wrapped" if c.wrapped_by_cerberus else "UNWRAPPED"
            tools = f" tools={list(c.tools_registered)}" if c.tools_registered else ""
            print(
                f"  {c.file}:{c.line}  [{c.framework}] {c.symbol}"
                f" ({wrapped}){tools}",
                file=out,
            )
    if report.mcp_servers:
        print("", file=out)
        print("MCP servers:", file=out)
        for m in report.mcp_servers:
            cmd = f" cmd={m.command}" if m.command else ""
            print(f"  {m.name}  config={m.config_path}{cmd}", file=out)
    if report.errors:
        print("", file=out)
        print("Errors:", file=out)
        for e in report.errors:
            print(f"  - {e}", file=out)


def run_discover(args: argparse.Namespace) -> int:
    report = scan_repo(args.root, include_mcp_home=args.include_mcp_home)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            if args.format == "json":
                json.dump(report.to_dict(), fh, indent=2, sort_keys=True)
                fh.write("\n")
            else:
                _render_text(report, fh)
    else:
        if args.format == "json":
            json.dump(report.to_dict(), sys.stdout, indent=2, sort_keys=True)
            sys.stdout.write("\n")
        else:
            _render_text(report, sys.stdout)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "discover":
        return run_discover(args)
    parser.error(f"unknown command: {args.command}")
    return 2  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
