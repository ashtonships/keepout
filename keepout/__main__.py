"""python3 -m keepout entry point."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import platform

from .checks import evaluate, make_checks
from .codex import CodexRunner
from .policy import load_policy
from .report import markdown, write_report


def main() -> int:
    parser = argparse.ArgumentParser(prog="keepout")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="run disposable probes against a declared policy")
    run.add_argument("--harness", choices=["codex"], required=True)
    run.add_argument("--policy", required=True)
    run.add_argument("--json", metavar="FILE")
    run.add_argument("--md", metavar="FILE")
    sub.add_parser("list-checks", help="list checks in the bundled example policy")
    args = parser.parse_args()
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
            policy.protected_paths, policy.network, policy.inherit_fake_token)]
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
        },
        "checks": checks,
    }
    write_report(report, args.json, args.md)
    print(markdown(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
