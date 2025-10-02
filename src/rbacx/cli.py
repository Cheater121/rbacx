
from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .dsl.lint import analyze_policy, analyze_policyset
from .dsl.validate import validate_policy
from .store.policy_loader import parse_policy_text
from . import __version__


# ------------------------------- utils ---------------------------------


def _parse_require_attrs(s: str | None) -> Dict[str, List[str]]:
    """
    Parse --require-attrs string like:
        "subject:id,org;resource:type;:a,b"
    into:
        {"subject": ["id","org"], "resource": ["type"], "": ["a","b"]}
    Notes:
      - Keeps empty entity key '' if provided (back-compat with tests).
      - Ignores chunks without ':' (lenient as before).
    """
    if s is None:
        return {}
    out: Dict[str, List[str]] = {}
    for part in [p for p in s.split(";")]:
        if ":" not in part:
            # keep legacy leniency: skip malformed chunk silently
            continue
        key, csv = part.split(":", 1)
        # Do NOT drop empty key: tests expect '' to be preserved
        key = key.strip()
        values = [v.strip() for v in csv.split(",")]
        # filter out purely empty items but keep non-empty
        values = [v for v in values if v != ""]
        out[key] = values
    return out


def _read_text_from_path_or_stdin(path: Optional[str]) -> Tuple[str, Optional[str]]:
    """
    Read text from file path or STDIN when path is '-' or None.
    Returns (text, filename_for_format_detection).
    """
    if path and path != "-":
        with open(path, "r", encoding="utf-8") as f:
            return f.read(), path
    data = sys.stdin.read()
    return data, None


def _load_policy_from_arg(path: Optional[str]) -> Dict[str, Any]:
    """
    Read and parse a single text document (JSON or YAML) into a dict.
    May raise FileNotFoundError / json.JSONDecodeError, which tests expect.
    """
    text, fn = _read_text_from_path_or_stdin(path)
    return parse_policy_text(text, filename=fn)


def _format_issues_text(issues: Iterable[Dict[str, Any]]) -> str:
    """
    Human-friendly text formatter for lint issues.
    Keys may include: code, message, path, policy_index.
    """
    lines: List[str] = []
    for it in issues:
        code = it.get("code", "ISSUE")
        msg = it.get("message", "")
        path = it.get("path")
        pidx = it.get("policy_index")
        prefix = f"{code}"
        if pidx is not None:
            prefix += f" [policy_index={pidx}]"
        if path:
            prefix += f" {path}"
        if msg:
            prefix += f": {msg}"
        lines.append(prefix)
    return "\n".join(lines)


def _print(obj: Any, fmt: str) -> None:
    """
    Print helper honoring --format.
    """
    if fmt == "json":
        sys.stdout.write(json.dumps(obj, ensure_ascii=False))
        sys.stdout.write("\n")
    else:
        if isinstance(obj, str):
            sys.stdout.write(obj)
            if not obj.endswith("\n"):
                sys.stdout.write("\n")
        else:
            sys.stdout.write(str(obj) + "\n")


# Exit codes
EXIT_OK = 0
EXIT_USAGE = 2            # argparse uses 2 for usage errors
EXIT_LINT_ERRORS = 3      # used only when --strict
EXIT_IO = 4
EXIT_ENV = 5              # missing optional deps, etc.
EXIT_SCHEMA_ERRORS = 6


# ----------------------------- internal doc-based ops -------------------


def _lint_doc(doc: Dict[str, Any], *, policyset: bool, require_attrs: Dict[str, List[str]]):
    if policyset:
        return analyze_policyset(doc, require_attrs=require_attrs)
    return analyze_policy(doc, require_attrs=require_attrs)


def _validate_doc(doc: Dict[str, Any], *, policyset: bool) -> List[Dict[str, Any]]:
    if policyset:
        errs: List[Dict[str, Any]] = []
        for idx, pol in enumerate(doc.get("policies") or []):
            try:
                validate_policy(pol)
            except RuntimeError:
                # Bubble up to caller to translate into EXIT_ENV
                raise
            except Exception as e:
                it = {"message": str(e), "policy_index": idx}
                errs.append(it)
        return errs
    else:
        try:
            validate_policy(doc)
            return []
        except RuntimeError:
            raise
        except Exception as e:
            return [{"message": str(e)}]


# ----------------------------- commands --------------------------------


def cmd_lint(args: argparse.Namespace) -> int:
    """
    Lint a policy or a policy set.
    Historical default: return 0 even if there are issues (unless --strict).
    NOTE: FileNotFoundError / JSONDecodeError are intentionally not caught
          to satisfy test expectations.
    """
    fmt = getattr(args, "format", "json")
    require = _parse_require_attrs(getattr(args, "require_attrs", None))
    strict = bool(getattr(args, "strict", False))

    # Old semantics: --policy PATH (or STDIN), and boolean --policyset
    doc = _load_policy_from_arg(getattr(args, "policy", None))
    issues = _lint_doc(doc, policyset=getattr(args, "policyset", False), require_attrs=require)

    issues_list = list(issues)
    if fmt == "json":
        _print(issues_list, "json")
    else:
        _print(_format_issues_text(issues_list), "text")

    if strict and issues_list:
        return EXIT_LINT_ERRORS
    return EXIT_OK


def cmd_validate(args: argparse.Namespace) -> int:
    """
    Validate a policy or policy set against the JSON Schema.
    Uses same old semantics: input from --policy PATH|- or STDIN; boolean --policyset switches mode.
    """
    fmt = getattr(args, "format", "json")

    try:
        doc = _load_policy_from_arg(getattr(args, "policy", None))
        errs = _validate_doc(doc, policyset=getattr(args, "policyset", False))
    except RuntimeError as e:
        # missing optional dependency for validate
        _print(str(e), "text")
        return EXIT_ENV

    if fmt == "json":
        _print(errs, "json")
    else:
        if errs:
            lines = []
            for it in errs:
                msg = it.get("message", "")
                pidx = it.get("policy_index")
                prefix = "SCHEMA"
                if pidx is not None:
                    prefix += f" [policy_index={pidx}]"
                if msg:
                    prefix += f": {msg}"
                lines.append(prefix)
            _print("\n".join(lines), "text")
        else:
            _print("OK", "text")

    return EXIT_OK if not errs else EXIT_SCHEMA_ERRORS


def cmd_check(args: argparse.Namespace) -> int:
    """
    Combined 'validate' then 'lint'.
    --strict affects only the lint phase (validation always fails on schema errors).
    Reads and parses the input ONCE (stdin/file), then reuses the parsed document.
    """
    fmt = getattr(args, "format", "json")
    require = _parse_require_attrs(getattr(args, "require_attrs", None))
    strict = bool(getattr(args, "strict", False))
    is_policyset = bool(getattr(args, "policyset", False))

    # Buffer the parsed input so stdin is consumed once.
    doc = _load_policy_from_arg(getattr(args, "policy", None))

    # Validate phase
    try:
        errs = _validate_doc(doc, policyset=is_policyset)
    except RuntimeError as e:
        _print(str(e), "text")
        return EXIT_ENV

    # Print validate output in requested format
    if fmt == "json":
        _print(errs, "json")
    else:
        if errs:
            lines = []
            for it in errs:
                msg = it.get("message", "")
                pidx = it.get("policy_index")
                prefix = "SCHEMA"
                if pidx is not None:
                    prefix += f" [policy_index={pidx}]"
                if msg:
                    prefix += f": {msg}"
                lines.append(prefix)
            _print("\n".join(lines), "text")
        else:
            _print("OK", "text")

    if errs:
        return EXIT_SCHEMA_ERRORS

    # Lint phase on the same buffered doc
    issues = _lint_doc(doc, policyset=is_policyset, require_attrs=require)
    issues_list = list(issues)
    if fmt == "json":
        _print(issues_list, "json")
    else:
        _print(_format_issues_text(issues_list), "text")

    if strict and issues_list:
        return EXIT_LINT_ERRORS
    return EXIT_OK


# ------------------------------ parser ---------------------------------


def _add_common_io_args(p: argparse.ArgumentParser) -> None:
    """
    Old semantics kept:
      --policy PATH|-     (reads JSON/YAML; '-' or omit => STDIN)
      --policyset         (boolean flag: interpret input as policy set)
    """
    src = p.add_argument_group("Input")
    src.add_argument(
        "--policy",
        metavar="PATH|-",
        help="Path to a policy file (JSON/YAML). Use '-' or omit to read from STDIN.",
    )
    src.add_argument(
        "--policyset",
        action="store_true",
        help="Treat input as a policy set (expects top-level 'policies').",
    )


def _add_common_format_args(p: argparse.ArgumentParser) -> None:
    fmt = p.add_argument_group("Output")
    fmt.add_argument(
        "--format",
        choices=("json", "text"),
        default="json",
        help="Output format (default: json).",
    )
    fmt.add_argument(
        "--strict",
        action="store_true",
        help="Return non-zero exit code when lint finds issues.",
    )


def add_lint_subparser(subparsers: argparse._SubParsersAction) -> None:
    pl = subparsers.add_parser(
        "lint",
        help="Run the DSL linter on a policy or a policy set.",
        description="Analyze policy structure for common pitfalls (non-schema checks).",
    )
    _add_common_io_args(pl)
    _add_common_format_args(pl)
    pl.add_argument(
        "--require-attrs",
        dest="require_attrs",
        default=None,
        help='Require attribute keys by entity, e.g. "subject:id,org;resource:type;:a,b".',
    )
    pl.set_defaults(func=cmd_lint)


def add_validate_subparser(subparsers: argparse._SubParsersAction) -> None:
    pv = subparsers.add_parser(
        "validate",
        help="Validate policy against the JSON Schema.",
        description="Validate a policy or each entry of a policy set using the official JSON Schema.",
    )
    _add_common_io_args(pv)
    _add_common_format_args(pv)
    pv.set_defaults(func=cmd_validate)


def add_check_subparser(subparsers: argparse._SubParsersAction) -> None:
    pc = subparsers.add_parser(
        "check",
        help="Run validation then lint.",
        description="Convenience command to run schema validation first, then lint.",
    )
    _add_common_io_args(pc)
    _add_common_format_args(pc)
    pc.add_argument(
        "--require-attrs",
        dest="require_attrs",
        default=None,
        help='Only affects the lint phase. Example: "subject:id,org;resource:type".',
    )
    pc.set_defaults(func=cmd_check)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="rbacx",
        description="RBACX DSL utilities: validate and lint policies for CI and local use.",
    )
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="command", metavar="COMMAND")
    add_lint_subparser(sub)
    add_validate_subparser(sub)
    add_check_subparser(sub)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    # Prevent argparse from raising SystemExit(0) on --version.
    try:
        args = parser.parse_args(argv)
    except SystemExit as e:
        # argparse prints the version/help itself; normalize to return code.
        # We only swallow the exit if it was a normal (0) exit,
        # otherwise re-raise so tests expecting failure can see it.
        if e.code == 0 and argv and any(a in ("-v", "--version") for a in argv):
            return EXIT_OK
        raise

    if not hasattr(args, "func"):
        parser.print_help()
        return EXIT_USAGE
    rc = args.func(args)
    try:
        code = int(rc)
    except Exception:
        code = EXIT_OK
    return code


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

