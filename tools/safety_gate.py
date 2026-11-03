#!/usr/bin/env python3
"""Deterministic safety gate CLI: audit the converter, extracted text, or a generated skill.

Exit codes: 0 pass (advisory findings may be listed), 1 blocked, 2 check incomplete.
"""

from __future__ import annotations

import argparse
import sys

if __name__ == "__main__":
    sys.dont_write_bytecode = True
from pathlib import Path
from typing import Sequence

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from book_to_skill import safety_gate as gate  # noqa: E402
import scan_generated_skill as scanner  # noqa: E402


def _terminal_safe(value: str) -> str:
    return value.encode("unicode_escape", errors="backslashreplace").decode("ascii")


def _run_self(root: Path) -> tuple[list[gate.Finding], dict]:
    return gate.audit_converter(root), {"subject": "converter", "root": str(root.resolve())}


def _run_extracted(path: Path) -> tuple[list[gate.Finding], dict]:
    target = path.expanduser()
    if target.is_dir():
        for name in ("full_text.txt", gate.QUARANTINE_FILENAME):
            if (target / name).is_file():
                target = target / name
                break
        else:
            raise gate.GateError(f"{path} holds neither full_text.txt nor {gate.QUARANTINE_FILENAME}")
    if target.is_symlink() or not target.is_file():
        raise gate.GateError(f"{path} is not a regular file")
    try:
        text = target.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        raise gate.GateError(f"could not read {path}: {exc.__class__.__name__}") from exc
    return gate.classify_text(text, target.name), {"subject": "extracted", "path": str(target)}


def _run_generated(path: Path) -> tuple[list[gate.Finding], dict]:
    try:
        raw = scanner.scan_generated_skill(path)
        skipped = scanner.unscanned_markdown(path)
    except scanner.ScanError as exc:
        raise gate.GateError(str(exc)) from exc
    findings = [gate.Finding(f.path, f.line, f.rule_id, f.message) for f in raw]
    return findings, {"subject": "generated", "path": str(path), "unscanned": skipped}


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("subject", choices=("self", "extracted", "generated"))
    parser.add_argument("path", nargs="?", help="converter root (self), workdir or text file (extracted), skill dir (generated)")
    parser.add_argument("--json", action="store_true", help="print the report as JSON")
    args = parser.parse_args(argv)

    try:
        if args.subject == "self":
            findings, extra = _run_self(Path(args.path) if args.path else gate.converter_root())
        elif args.subject == "extracted":
            if not args.path:
                parser.error("extracted requires a workdir or text file path")
            findings, extra = _run_extracted(Path(args.path))
        else:
            if not args.path:
                parser.error("generated requires a skill directory path")
            findings, extra = _run_generated(Path(args.path))
    except gate.GateError as exc:
        if args.json:
            print(gate.dump_report({"rules_version": gate.RULES_VERSION, "verdict": "incomplete", "error": str(exc)}), end="")
        else:
            print(f"ERROR safety gate incomplete: {_terminal_safe(str(exc))}", file=sys.stderr)
        return gate.EXIT_INCOMPLETE

    report = gate.report_dict(findings, **extra)
    if args.json:
        print(gate.dump_report(report), end="")
    else:
        for item in report["findings"]:
            tag = "BLOCK" if item["severity"] == gate.BLOCK else "WARN "
            print(f"  {tag} {_terminal_safe(item['path'])}:{item['line']} [{item['rule_id']}] {item['message']}")
        for relative in extra.get("unscanned", []):
            print(f"  SKIP  {_terminal_safe(relative)} (outside the generated-skill scope; not scanned)")
        print(
            f"Safety gate [{args.subject}] verdict: {report['verdict'].upper()} "
            f"({report['blocking']} blocking, {report['advisory']} advisory; rules v{gate.RULES_VERSION})"
        )
        if report["verdict"] == gate.BLOCK:
            print("Stop. Do not read, load, install or publish this content until a human resolves the blocking findings.")
    return gate.EXIT_BLOCK if report["verdict"] == gate.BLOCK else gate.EXIT_PASS


if __name__ == "__main__":
    sys.exit(main())
