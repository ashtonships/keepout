"""Release watch: rerun the suite only when no result exists for this CLI version, OS and policy.

No scheduler is installed; run it by hand or from a scheduler you own.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import platform
import re
import sys
from typing import Callable

from . import codex, matrix, suite
from .policy import load_policy
from .report import markdown, write_report


LOG_NAME = "watch-log.jsonl"


def _log(results: Path, now: datetime, harness: str, version: str | None, os_name: str, action: str,
         result_file: str | None = None, reason: str | None = None) -> None:
    results.mkdir(parents=True, exist_ok=True)
    line = {"checked_at": now.astimezone(timezone.utc).isoformat(timespec="seconds"), "harness": harness,
            "cli_version": version, "os": os_name, "action": action, "result_file": result_file, "reason": reason}
    with (results / LOG_NAME).open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(line, sort_keys=True) + "\n")


def _matches(results: Path, version: str, os_name: str, policy: dict) -> str | None:
    for file in sorted(results.glob("*.json")):
        try:
            run = matrix.load_results([str(file)])[0]
        except (matrix.MatrixError, IndexError) as exc:
            print(f"keepout watch: skipping {file.name}: {exc}", file=sys.stderr)
            continue
        if (run["harness"] == suite.HARNESS and run["cli_version"] == version and run["os"] == os_name
                and run.get("policy") == policy and not run.get("superseded_note")):
            return file.name
    return None


def result_stem(results: Path, now: datetime, os_name: str, version: str) -> str:
    date = now.astimezone(timezone.utc).strftime("%Y-%m-%d")
    os_short = re.sub(r"[^0-9a-z._-]", "", os_name.split("-")[0].lower()) or "os"
    token = re.sub(r"[^0-9A-Za-z._-]", "", matrix.version_token(version)) or "unknown"
    for suffix in [""] + [chr(code) for code in range(ord("b"), ord("z") + 1)]:
        stem = f"{date}{suffix}-{os_short}-codex-{token}"
        if not (results / (stem + ".json")).exists() and not (results / (stem + ".md")).exists():
            return stem
    raise RuntimeError("too many results for one day")


def watch(harness: str, policy_path: str, results_dir: str, *, dry_run: bool = False, force: bool = False,
          version_fn: Callable[[], str] = codex.cli_version, suite_fn: Callable = suite.run_suite,
          now: datetime | None = None, os_name: str | None = None) -> int:
    if harness != "codex":
        raise ValueError("only harness 'codex' is supported in v0")
    os_name = os_name or platform.platform()
    now = now or datetime.now(timezone.utc)
    results = Path(results_dir)
    policy = load_policy(policy_path)
    try:
        version = version_fn()
    except (FileNotFoundError, RuntimeError) as exc:
        reason = f"UNMEASURED: codex CLI not found / version failed: {type(exc).__name__}"
        if not dry_run:
            _log(results, now, harness, None, os_name, "error", reason=reason)
        print(reason)
        return 2
    match = _matches(results, version, os_name, suite.policy_dict(policy))
    if match and not force:
        print(f"up to date: {match} ({version})")
        if not dry_run:
            _log(results, now, harness, version, os_name, "skipped", result_file=match)
        return 0
    if dry_run:
        print(f"would run: {version} (no result for this version/os/policy)" if not match else
              f"would run: {version} (--force; existing result {match})")
        return 0
    report = suite_fn(policy)
    try:
        after = version_fn()
    except (FileNotFoundError, RuntimeError) as exc:
        after = f"unavailable ({type(exc).__name__})"
    if after != version:
        reason = "CLI version changed during run"
        _log(results, now, harness, version, os_name, "error", reason=f"{reason}: {version} -> {after}")
        print(f"keepout watch: {reason} ({version} -> {after}); nothing written")
        return 2
    stem = result_stem(results, now, os_name, version)
    write_report(report, str(results / (stem + ".json")), str(results / (stem + ".md")))
    _log(results, now, harness, version, os_name, "ran", result_file=stem + ".json")
    print(markdown(report))
    return suite.exit_code(report)
