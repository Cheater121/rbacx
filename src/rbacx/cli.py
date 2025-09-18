from __future__ import annotations

import argparse
import json
from typing import Dict, List

from .dsl.lint import analyze_policy, analyze_policyset
from .store.policy_loader import parse_policy_text


def _parse_require_attrs(s: str | None) -> Dict[str, List[str]]:
    if not s:
        return {}
    out: Dict[str, List[str]] = {}
    parts = [p for p in s.split(";") if p]
    for part in parts:
        if ":" in part:
            typ, attrs = part.split(":", 1)
            out[typ.strip()] = [a.strip() for a in attrs.split(",") if a.strip()]
    return out


def cmd_lint(args: argparse.Namespace) -> None:
    with open(args.policy, "r", encoding="utf-8") as f:
        text = f.read()
    data = parse_policy_text(text, filename=args.policy)
    req = _parse_require_attrs(getattr(args, "require_attrs", None))
    issues = (
        analyze_policyset(data, require_attrs=req)
        if isinstance(data, dict) and "policies" in data
        else analyze_policy(data, require_attrs=req)
    )
    print(json.dumps(issues, ensure_ascii=False, indent=2))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser("rbacx", description="RBACX CLI")
    sub = p.add_subparsers(dest="command")

    pl = sub.add_parser("lint", help="Lint policy or policyset (JSON/YAML)")
    pl.add_argument("--policy", required=True, help="Path to policy file (.json/.yaml/.yml)")
    pl.add_argument(
        "--require-attrs",
        dest="require_attrs",
        default=None,
        help='Format: "subject:a,b;resource:x,y"',
    )
    pl.set_defaults(func=cmd_lint)
    return p


def main(argv: List[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "func"):
        parser.print_help()
        return
    args.func(args)
