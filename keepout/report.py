"""Stable, human-readable and machine-readable results."""

from __future__ import annotations

import json
from pathlib import Path

from .checks import public_result


def public_report(report: dict) -> dict:
    return dict(report, checks=[public_result(check) for check in report["checks"]])


def summary(report: dict) -> dict[str, object]:
    checks = report["checks"]
    counts = {name: sum(check["verdict"] == name for check in checks)
              for name in ("PASS", "FAIL", "INVALID", "UNMEASURED", "EXPECTED-VISIBLE")}
    failed_allowed = [check["id"] for check in checks if check["id"].startswith("allowed-")
                      and check["verdict"] != "PASS"]
    counts["enforcement_failures"] = sum(
        check["verdict"] == "FAIL" and check["expectation"] == "deny" for check in checks)
    counts["status"] = ("INVALID: sandbox blocked allowed actions; denials prove nothing"
                        if failed_allowed else
                        "INVALID: omitted-rule control failed; denials prove nothing"
                        if report["rule_omission"]["verdict"] != "PASS" else "controls passed")
    return counts


def markdown(report: dict) -> str:
    report = public_report(report)
    totals = summary(report)
    lines = [
        "# Keepout result",
        "",
        f"- Harness: `{report['harness']}`",
        f"- CLI: `{report['cli_version']}`",
        f"- OS: `{report['os']}`",
        f"- Run time (UTC): `{report['date']}`",
        f"- Summary: {totals['status']}; PASS {totals['PASS']}, FAIL {totals['FAIL']}, "
        f"INVALID {totals['INVALID']}, UNMEASURED {totals['UNMEASURED']}, "
        f"EXPECTED-VISIBLE {totals['EXPECTED-VISIBLE']}; enforcement failures {totals['enforcement_failures']}",
        f"- Generated network setting: `{report['profile_receipt']['generated_profile_network_mode']}`",
        f"- Effective profile readback: {report['profile_receipt']['codex_effective_profile_readback']}",
        f"- Strict config: {report['profile_receipt']['strict_config']}",
        f"- Omitted-rule fail-closed check: {report['rule_omission']['verdict']} "
        f"(probe without rule: {report['rule_omission']['probe_verdict_without_rule']})",
        f"- Omitted-rule configuration: `{report['rule_omission']['omitted_profile_override']}`",
        *[f"- {label}: {report['profile_receipt'][key]}" for key, label in (
            ("node_version", "Node"), ("platform_scope", "Platform scope"),
            ("default_writable_note", "Default writable paths")) if key in report["profile_receipt"]],
        "",
        "Allowed-action controls run inside the sandbox. A denial PASS also requires an exposed unsandboxed control. "
        "If any allowed action fails, all denial verdicts are INVALID.",
        "",
        "## Generated configuration (temporary paths redacted)",
        "",
        *["- `" + item.replace("`", "") + "`" for item in report["profile_receipt"]["config_overrides"]],
        "- Environment override scope: " + report["profile_receipt"]["environment_override_scope"],
        "",
        "| Check | Verdict | Classification | Control evidence | Sandbox evidence |",
        "| --- | --- | --- | --- | --- |",
    ]
    for check in report["checks"]:
        cells = (check["id"], check["verdict"], check["classification"],
                 check["control_evidence"], check["sandbox_evidence"])
        lines.append("| " + " | ".join(str(cell).replace("|", "\\|").replace("\n", " ") for cell in cells) + " |")
    if report.get("unreachable"):
        lines.extend(["", "## Not reachable without a model turn (UNMEASURED)", ""])
        lines.extend("- " + item for item in report["unreachable"])
    return "\n".join(lines) + "\n"


def write_report(report: dict, json_path: str | None, md_path: str | None) -> None:
    report = public_report(report)
    if json_path:
        path = Path(json_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if md_path:
        path = Path(md_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(markdown(report), encoding="utf-8")
