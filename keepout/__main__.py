"""python3 -m keepout entry point."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import platform

from .checks import evaluate, invalidate_denials, make_checks
from .codex import CodexRunner
from .policy import load_policy
from .report import markdown, summary, write_report


def main() -> int:
    parser = argparse.ArgumentParser(prog="keepout")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="run disposable probes against a declared policy or an existing Codex profile")
    run.add_argument("--harness", choices=["codex"], required=True)
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
    args = parser.parse_args()
    if args.command == "lint":
        return _lint(args)
    if args.command == "run" and args.config:
        return _run_imported(args, parser)
    if args.command == "list-checks":
        from pathlib import Path
        policy = load_policy(Path(__file__).resolve().parents[1] / "policy.toml")
        for check in make_checks(policy.protected_paths, policy.network, policy.inherit_fake_token):
            print(f"{check.id}: {check.description}")
        return 0
    policy = load_policy(args.policy)
    with CodexRunner(policy) as runner:
        version = runner.version()
        checks = [evaluate(check, runner) for check in make_checks(
            policy.protected_paths, policy.network, policy.inherit_fake_token, policy.external_routes)]
        omission = runner.rule_omission()
        checks = invalidate_denials(checks, omission["verdict"] == "PASS")
        receipt = runner.receipt()
    report = {
        "harness": "codex sandbox named permission profile",
        "cli_version": version,
        "os": platform.platform(),
        "date": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "policy": {
            "protected_paths": list(policy.protected_paths),
            "writable_paths": list(policy.writable_paths),
            "network": policy.network,
            "inherit_fake_token": policy.inherit_fake_token,
            "external_routes": policy.external_routes,
        },
        "profile_receipt": receipt,
        "rule_omission": omission,
        "checks": checks,
    }
    write_report(report, args.json, args.md)
    print(markdown(report))
    totals = summary(report)
    return 1 if totals["FAIL"] or totals["INVALID"] or omission["verdict"] != "PASS" else 0


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
