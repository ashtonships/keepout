"""Stable, human-readable and machine-readable results."""

from __future__ import annotations

import json
from pathlib import Path


def markdown(report: dict) -> str:
    lines = [
        "# Keepout result",
        "",
        f"- Harness: `{report['harness']}`",
        f"- CLI: `{report['cli_version']}`",
        f"- OS: `{report['os']}`",
        f"- Run time (UTC): `{report['date']}`",
        "",
        "A PASS requires the unsandboxed control to observe the exposure and the sandboxed probe to match the policy. "
        "INVALID means the control did not prove the probe. UNMEASURED means the sandbox result was inconclusive or the probe was not run.",
        "",
        "| Check | Verdict | Control evidence | Sandbox evidence |",
        "| --- | --- | --- | --- |",
    ]
    for check in report["checks"]:
        cells = (check["id"], check["verdict"], check["control_evidence"], check["sandbox_evidence"])
        lines.append("| " + " | ".join(str(cell).replace("|", "\\|").replace("\n", " ") for cell in cells) + " |")
    return "\n".join(lines) + "\n"


def write_report(report: dict, json_path: str | None, md_path: str | None) -> None:
    if json_path:
        path = Path(json_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if md_path:
        path = Path(md_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(markdown(report), encoding="utf-8")
