"""python3 -m keepout entry point."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import platform

from .checks import evaluate, invalidate_denials, make_checks
from .claude import ClaudeRunner
from .codex import CodexRunner
from .policy import load_policy
from .report import markdown, summary, write_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="keepout")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="run disposable probes against a declared policy")
    run.add_argument("--harness", choices=["codex", "claude"], required=True)
    run.add_argument("--policy", required=True)
    run.add_argument("--json", metavar="FILE")
    run.add_argument("--md", metavar="FILE")
    sub.add_parser("list-checks", help="list checks in the bundled example policy")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "list-checks":
        from pathlib import Path
        policy = load_policy(Path(__file__).resolve().parents[1] / "policy.toml")
        for check in make_checks(policy.protected_paths, policy.network, policy.inherit_fake_token):
            print(f"{check.id}: {check.description}")
        return 0
    policy = load_policy(args.policy)
    runner_class = ClaudeRunner if args.harness == "claude" else CodexRunner
    with runner_class(policy) as runner:
        version = runner.version()
        planned = make_checks(policy.protected_paths, policy.network, policy.inherit_fake_token,
                              policy.external_routes)
        if hasattr(runner, "adjust"):
            planned = runner.adjust(planned)
        checks = [evaluate(check, runner) for check in planned]
        omission = runner.rule_omission()
        checks = invalidate_denials(checks, omission["verdict"] == "PASS")
        receipt = runner.receipt()
    report = {
        "harness": runner.HARNESS.format(version=version),
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
        "unreachable": receipt.get("unreachable_without_model_turn", []),
    }
    write_report(report, args.json, args.md)
    print(markdown(report))
    totals = summary(report)
    return 1 if totals["FAIL"] or totals["INVALID"] or omission["verdict"] != "PASS" else 0


if __name__ == "__main__":
    raise SystemExit(main())
