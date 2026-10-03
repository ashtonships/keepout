"""One full probe run, shared by `run` and `watch`."""

from __future__ import annotations

from datetime import datetime, timezone
import platform
from typing import Any, Callable

from .checks import evaluate, invalidate_denials, make_checks
from .codex import CodexRunner
from .policy import Policy
from .report import summary


HARNESS = "codex sandbox named permission profile"


def policy_dict(policy: Policy) -> dict[str, object]:
    """The policy exactly as a saved result records it."""
    return {
        "protected_paths": list(policy.protected_paths),
        "writable_paths": list(policy.writable_paths),
        "network": policy.network,
        "inherit_fake_token": policy.inherit_fake_token,
        "external_routes": policy.external_routes,
    }


def run_suite(policy: Policy, runner_factory: Callable[[Policy], Any] = CodexRunner) -> dict:
    with runner_factory(policy) as runner:
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
        "harness": getattr(runner, "HARNESS", HARNESS).format(version=version),
        "cli_version": version,
        "os": platform.platform(),
        "date": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "policy": policy_dict(policy),
        "profile_receipt": receipt,
        "rule_omission": omission,
        "checks": checks,
    }
    if "unreachable_without_model_turn" in receipt:
        report["unreachable"] = receipt["unreachable_without_model_turn"]
    return report


def exit_code(report: dict) -> int:
    totals = summary(report)
    return 1 if totals["FAIL"] or totals["INVALID"] or report["rule_omission"]["verdict"] != "PASS" else 0
