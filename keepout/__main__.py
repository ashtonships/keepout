"""python3 -m keepout entry point."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from .checks import make_checks
from .policy import load_policy
from .report import markdown, write_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="keepout")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="run disposable probes against a declared policy or an existing Codex profile")
    run.add_argument("--harness", choices=["codex", "claude"], required=True)
    source = run.add_mutually_exclusive_group(required=True)
    source.add_argument("--policy", help="a Keepout test policy")
    source.add_argument("--config", help="an existing Codex config.toml (remapped into a disposable root)")
    run.add_argument("--profile", help="the [permissions.<name>] profile to run (with --config)")
    run.add_argument("--i-own-this-file", action="store_true",
                     help="allow a config under ~/.codex, ~/.claude, ~/.ssh or ~/.config (only that file is read)")
    run.add_argument("--json", metavar="FILE")
    run.add_argument("--md", metavar="FILE")
    lint = sub.add_parser("lint", help="lint an existing Codex config (static; --codex-check runs Codex)")
    lint.add_argument("config")
    lint.add_argument("--profile")
    lint.add_argument("--json", metavar="FILE")
    lint.add_argument("--codex-check", action="store_true",
                      help="also start Codex against a dead local provider with a sanitized copy")
    lint.add_argument("--i-own-this-file", action="store_true")
    sub.add_parser("list-checks", help="list checks in the bundled example policy")
    matrix = sub.add_parser("matrix", help="render saved results as a public matrix")
    matrix.add_argument("paths", nargs="+", metavar="PATH", help="result .json files or directories")
    matrix.add_argument("--html", metavar="FILE")
    matrix.add_argument("--md", metavar="FILE")
    watch = sub.add_parser("watch", help="run the suite only when the installed CLI has no result yet")
    watch.add_argument("--harness", choices=["codex"], required=True)
    watch.add_argument("--policy", required=True)
    watch.add_argument("--results", required=True, metavar="DIR")
    watch.add_argument("--dry-run", action="store_true")
    watch.add_argument("--force", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "lint":
        return _lint(args)
    if args.command == "run" and args.config:
        if args.harness != "codex":
            parser.error("--config reads a Codex config; use --harness codex")
        return _run_imported(args, parser)
    if args.command == "list-checks":
        policy = load_policy(Path(__file__).resolve().parents[1] / "policy.toml")
        for check in make_checks(policy.protected_paths, policy.network, policy.inherit_fake_token):
            print(f"{check.id}: {check.description}")
        return 0
    if args.command == "matrix":
        return _matrix(parser, args)
    if args.command == "watch":
        from .watch import watch as run_watch
        return run_watch(args.harness, args.policy, args.results, dry_run=args.dry_run, force=args.force)
    from .suite import exit_code, run_suite
    if args.harness == "claude":
        from .claude import ClaudeRunner as runner_class
    else:
        from .codex import CodexRunner as runner_class
    report = run_suite(load_policy(args.policy), runner_class)
    write_report(report, args.json, args.md)
    print(markdown(report))
    return exit_code(report)


def _matrix(parser: argparse.ArgumentParser, args: argparse.Namespace) -> int:
    from . import matrix
    if not args.html and not args.md:
        parser.error("matrix needs --html FILE, --md FILE or both")
    try:
        model = matrix.build_model(matrix.load_results(args.paths))
        outputs = []  # render everything before writing anything
        if args.html:
            outputs.append((args.html, matrix.render_html(model)))
        if args.md:
            outputs.append((args.md, matrix.render_markdown(model)))
    except matrix.MatrixError as exc:
        print(f"keepout matrix: {exc}", file=sys.stderr)
        return 2
    for name, text in outputs:
        path = Path(name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return 0


def _lint(args: argparse.Namespace) -> int:
    import json
    from pathlib import Path
    from . import lint
    from .codexconfig import ConfigError, RefusedPath, load_codex_config
    try:
        findings = lint.lint_file(args.config, args.profile, args.i_own_this_file)
    except RefusedPath as exc:
        print(f"refused: {exc}")
        return 2
    receipt = None
    if args.codex_check and not any(item["id"] == "KO001" for item in findings):
        receipt = lint.codex_check(load_codex_config(args.config, args.i_own_this_file), findings)
        findings = lint._sorted(findings)
    if args.json:
        path = Path(args.json)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = findings if receipt is None else {"findings": findings, "codex_check": receipt}
        path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(lint.render(findings), end="")
    if receipt:
        print(receipt["note"])
    return lint.exit_code(findings)


def _run_imported(args: argparse.Namespace, parser: argparse.ArgumentParser) -> int:
    from . import imported
    from .codexconfig import ConfigError, RefusedPath, load_codex_config
    try:
        cfg = load_codex_config(args.config, args.i_own_this_file)
    except RefusedPath as exc:
        print(f"refused: {exc}")
        return 2
    except ConfigError as exc:
        print(f"config does not parse (KO001): {exc}")
        return 2
    name = args.profile or cfg.default_permissions
    if not isinstance(name, str) or name not in cfg.profiles:
        parser.error(f"--profile must name a [permissions.<name>] profile in {args.config}")
    try:
        runner = imported.ImportedRunner(cfg, name)
    except ConfigError as exc:
        print(f"profile does not resolve (KO043): {exc}")
        return 2
    with runner:
        report = runner.run()
    imported.write_report(report, args.json, args.md)
    print(imported.markdown(report))
    return imported.exit_code(report)


if __name__ == "__main__":
    raise SystemExit(main())
