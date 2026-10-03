"""A public results matrix from saved result JSON files.

Deterministic, standard library only. It reads only already-public result files, sends every check through the
publication boundary again, refuses to render anything that looks like an unredacted path or canary, and applies
the held rule: a run with any held check withholds every denial cell, so the held check cannot be found by
elimination.
"""

from __future__ import annotations

import html
import json
from pathlib import Path
import re

from .checks import HELD, public_result
from .report import summary


SCOPE = ("Each result applies only to the tested CLI version, policy, machine and routes. "
         "It is not a security certification and does not establish a vendor vulnerability.")
LEGACY_STATUS = ("legacy run: allowed-action and omitted-rule controls not recorded; "
                 "denials not control-validated")
DENY_PREFIXES = ("read-", "write-", "tcp-", "unix-", "dns-", "read-symlink")
REQUIRED = ("cli_version", "harness", "os", "date", "checks")
NONE = "—"
HELD_CELL = "held"
ROW_CONTROLS = "controls: allowed actions"
ROW_OMISSION = "controls: omitted-rule fail-closed"
ROW_STATUS = "run status"

_LEAK_PATH = re.compile(r"(/private/tmp/keepout-|/var/folders/|/Users/|/home/)\S")
_LEAK_TOKEN = re.compile(r"(keepout|fake)-[0-9a-f]{48}")
_VERSION = re.compile(r"\d+(?:\.\d+)*[0-9A-Za-z.+-]*")


class MatrixError(ValueError):
    pass


# ---------------------------------------------------------------- loading


def load_results(paths: list[str]) -> list[dict]:
    files: list[Path] = []
    for item in paths:
        path = Path(item)
        if path.is_dir():
            files.extend(sorted(child for child in path.glob("*.json") if child.is_file()))
        elif path.is_file() and path.suffix == ".json":
            files.append(path)
    runs = []
    for file in files:
        try:
            data = json.loads(file.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise MatrixError(f"{file.name}: not a readable result JSON ({type(exc).__name__})") from None
        if not isinstance(data, dict):
            raise MatrixError(f"{file.name}: a result must be a JSON object")
        missing = [key for key in REQUIRED if key not in data]
        if missing or not isinstance(data["checks"], list):
            raise MatrixError(f"{file.name}: missing or invalid {', '.join(missing) or 'checks'}")
        data["_file"] = file.name
        runs.append(data)
    return runs


def _expectation(check_id: str) -> str:
    if check_id.startswith("allowed-"):
        return "allow"
    if check_id.startswith(DENY_PREFIXES):
        return "deny"
    return "unknown"


def normalize(run: dict) -> dict:
    checks = []
    for raw in run["checks"]:
        if not isinstance(raw, dict) or "id" not in raw or "verdict" not in raw:
            raise MatrixError(f"{run.get('_file', '?')}: a check lacks id or verdict")
        check = {key: str(value) for key, value in raw.items()}
        check.setdefault("expectation", _expectation(check["id"]))
        if "classification" not in check:
            # An unclassified FAIL from before the hold existed is held, never shown.
            check["classification"] = "pending_review" if check["verdict"] == "FAIL" else "unclassified (legacy)"
        check.setdefault("description", "")
        check.setdefault("control_evidence", "")
        check.setdefault("sandbox_evidence", "")
        checks.append(public_result(check))
    out = {key: value for key, value in run.items() if key != "checks"}
    out["checks"] = checks
    out["superseded"] = bool(run.get("superseded_note"))
    out["legacy"] = "rule_omission" not in run
    out["held_count"] = sum(check["classification"] in HELD for check in checks)
    if out["legacy"]:
        out["status"] = LEGACY_STATUS
    else:
        out["status"] = str(summary(out)["status"])
    return out


def scan_leaks(run: dict) -> None:
    def walk(value: object, where: str) -> None:
        if isinstance(value, dict):
            for key, item in value.items():
                walk(key, f"{where}.<key>")
                walk(item, f"{where}.{key}")
        elif isinstance(value, list):
            for index, item in enumerate(value):
                walk(item, f"{where}[{index}]")
        elif isinstance(value, str):
            text = value.replace("<temp>/home/", "<temp>/")
            if _LEAK_PATH.search(text) or _LEAK_TOKEN.search(text):
                raise MatrixError(f"{run.get('_file', '?')}: possible unredacted path or canary at {where}; "
                                  "refusing to render")
    walk(run, "$")


# ---------------------------------------------------------------- model


def version_token(cli_version: str) -> str:
    match = _VERSION.search(cli_version)
    return match.group(0) if match else cli_version


def _version_key(cli_version: str) -> tuple:
    token = version_token(cli_version)
    parts = token.split(".")
    if all(part.isdigit() for part in parts):
        return (0, tuple(int(part) for part in parts), token)
    numbers = re.findall(r"\d+", token)
    return (1, tuple(int(n) for n in numbers), token)


def short_harness(harness: str) -> str:
    return "codex" if harness.startswith("codex") else harness


def short_os(os_name: str) -> str:
    parts = os_name.split("-")
    return " ".join(parts[:2]) if len(parts) > 1 else os_name


def _header(run: dict) -> dict[str, str]:
    return {"harness": short_harness(str(run["harness"])), "version": version_token(str(run["cli_version"])),
            "os": short_os(str(run["os"])), "date": str(run["date"])[:10]}


def build_model(runs: list[dict]) -> dict:
    normalized = []
    for run in runs:
        item = normalize(run)
        scan_leaks(item)
        normalized.append(item)
    latest: dict[tuple, dict] = {}
    history = []
    for run in sorted(normalized, key=lambda r: (str(r["date"]), r.get("_file", ""))):
        if run["superseded"]:
            history.append(run)
            continue
        key = (str(run["harness"]), str(run["cli_version"]), str(run["os"]))
        if key in latest:
            history.append(latest[key])
        latest[key] = run
    columns = sorted(latest.values(), key=lambda r: (str(r["harness"]), _version_key(str(r["cli_version"])),
                                                    str(r["os"]), str(r["date"])))
    history.sort(key=lambda r: (str(r["date"]), r.get("_file", "")))
    for run in history:
        if run["superseded"]:
            run["history_reason"] = str(run["superseded_note"])
        else:
            run["history_reason"] = "older run for the same harness, CLI version and OS; the newest is in the matrix"

    expectations: dict[str, str] = {}
    newest_order: list[str] = []
    newest = max(columns, key=lambda r: (str(r["date"]), r.get("_file", "")), default=None)
    for run in ([newest] if newest else []) + [c for c in reversed(columns) if c is not newest]:
        for check in run["checks"]:
            if check["classification"] in HELD or check["id"] == "suspected-bypass":
                continue
            expectations.setdefault(check["id"], check["expectation"])
            if run is newest and check["id"] not in newest_order:
                newest_order.append(check["id"])
    others = sorted(set(expectations) - set(newest_order))
    ordered = newest_order + others
    rows = [i for i in ordered if i.startswith("allowed-")] + [i for i in ordered if not i.startswith("allowed-")]

    model_columns = []
    for run in columns:
        held = run["held_count"] > 0
        by_id = {c["id"]: c for c in run["checks"] if c["classification"] not in HELD}
        cells = {}
        for row in rows:
            if held and expectations[row] in ("deny", "unknown"):
                cells[row] = None  # held
            else:
                cells[row] = by_id.get(row)
        allowed = [c for c in run["checks"] if c["id"].startswith("allowed-")]
        controls = NONE if run["legacy"] or not allowed else (
            "PASS" if all(c["verdict"] == "PASS" for c in allowed) else "INVALID")
        omission = str(run["rule_omission"].get("verdict", NONE)) if not run["legacy"] else NONE
        model_columns.append({"run": run, "header": _header(run), "held": held, "cells": cells,
                              "controls": controls, "omission": omission})
    return {"columns": model_columns, "rows": rows, "expectations": expectations, "history": history,
            "run_count": len(normalized), "file_count": len({r.get("_file") for r in normalized})}


def _cell_text(model: dict, column: dict, row: str) -> str:
    if column["held"] and model["expectations"][row] in ("deny", "unknown"):
        return HELD_CELL
    check = column["cells"][row]
    return NONE if check is None else check["verdict"]


def _header_text(column: dict) -> str:
    h = column["header"]
    return f"{h['harness']} {h['version']} {h['os']} {h['date']}"


# ---------------------------------------------------------------- HTML


CSS = """
:root{--bg:#f7f7f5;--fg:#1d1d1f;--muted:#6e6e73;--line:#d9d9de;--panel:#ffffff;--sticky:#ffffff;
--pass-bg:#e3f4e8;--pass-fg:#17663a;--fail-bg:#fde4e2;--fail-fg:#a3261c;--invalid-bg:#fdf0d5;--invalid-fg:#8a5a00;
--unmeasured-bg:#ececef;--unmeasured-fg:#55555a;--visible-bg:#e2edfc;--visible-fg:#1d4f9c;
--held-a:#e4e4e8;--held-b:#d6d6db;--held-fg:#4a4a4f}
@media (prefers-color-scheme: dark){:root{--bg:#141416;--fg:#ececf0;--muted:#a1a1a8;--line:#36363c;--panel:#1c1c1f;
--sticky:#1c1c1f;--pass-bg:#173523;--pass-fg:#7fd99e;--fail-bg:#43201d;--fail-fg:#ff9b90;--invalid-bg:#3d3015;
--invalid-fg:#f2c56b;--unmeasured-bg:#2a2a2e;--unmeasured-fg:#b4b4ba;--visible-bg:#1b2c47;--visible-fg:#9cc3ff;
--held-a:#2b2b30;--held-b:#35353b;--held-fg:#c4c4ca}}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 -apple-system,system-ui,sans-serif}
main{max-width:1200px;margin:0 auto;padding:20px 16px 40px}
h1{font-size:20px;margin:0 0 4px}
h2{font-size:16px;margin:28px 0 8px}
p,li{color:var(--muted);overflow-wrap:anywhere}
.lede{margin:0 0 16px}
.wrap{overflow-x:auto;border:1px solid var(--line);border-radius:10px;background:var(--panel)}
table{border-collapse:separate;border-spacing:0;min-width:100%}
th,td{padding:6px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
thead th{font-weight:600;font-size:12px;white-space:nowrap;background:var(--panel)}
thead th span{display:block;font-weight:400;color:var(--muted)}
thead th .heldnote{color:var(--held-fg);font-weight:600;white-space:normal;max-width:14em}
th[scope=row]{position:sticky;left:0;background:var(--sticky);font-weight:500;font-family:ui-monospace,Menlo,monospace;
font-size:12px;white-space:nowrap;z-index:1}
thead th:first-child{position:sticky;left:0;z-index:2}
tr.extra th,tr.extra td{background:var(--panel)}
tr.extra th[scope=row]{font-family:inherit;color:var(--muted)}
td.status{font-size:12px;color:var(--muted);min-width:14em}
.v{display:inline-block;padding:1px 8px;border-radius:999px;font-weight:600;font-size:12px;white-space:nowrap}
.PASS{background:var(--pass-bg);color:var(--pass-fg)}
.FAIL{background:var(--fail-bg);color:var(--fail-fg)}
.INVALID{background:var(--invalid-bg);color:var(--invalid-fg)}
.UNMEASURED,.other{background:var(--unmeasured-bg);color:var(--unmeasured-fg)}
.EXPECTED-VISIBLE{background:var(--visible-bg);color:var(--visible-fg)}
.held{background:repeating-linear-gradient(135deg,var(--held-a) 0 6px,var(--held-b) 6px 12px);color:var(--held-fg)}
.none{color:var(--muted)}
details summary{cursor:pointer;list-style:none}
details summary::-webkit-details-marker{display:none}
details[open] summary{margin-bottom:6px}
dl{margin:0;font-size:12px;max-width:26em;white-space:normal}
dt{color:var(--muted);margin-top:4px}
dd{margin:0;overflow-wrap:anywhere;font-family:ui-monospace,Menlo,monospace}
.foot{margin-top:24px;font-size:12px}
"""


def _e(value: object) -> str:
    return html.escape(str(value), quote=True)


def _verdict_class(word: str) -> str:
    return word if word in ("PASS", "FAIL", "INVALID", "UNMEASURED", "EXPECTED-VISIBLE") else "other"


def _html_cell(model: dict, column: dict, row: str) -> str:
    text = _cell_text(model, column, row)
    if text == HELD_CELL:
        return '<td><span class="v held">held</span></td>'
    if text == NONE:
        return '<td><span class="none" title="not in this run">—</span></td>'
    check = column["cells"][row]
    fields = (("expectation", check["expectation"]), ("classification", check["classification"]),
              ("control evidence", check["control_evidence"]), ("sandbox evidence", check["sandbox_evidence"]),
              ("description", check["description"]))
    body = "".join(f"<dt>{_e(name)}</dt><dd>{_e(value)}</dd>" for name, value in fields)
    return (f'<td><details><summary class="v {_verdict_class(text)}" title="{_e("control: " + check["control_evidence"])}">'
            f'{_e(text)}</summary><dl>{body}</dl></details></td>')


def _plain_cell(word: str) -> str:
    if word == NONE:
        return '<td><span class="none">—</span></td>'
    return f'<td><span class="v {_verdict_class(word)}">{_e(word)}</span></td>'


def render_html(model: dict) -> str:
    cols = model["columns"]
    out = ["<!doctype html>", '<html lang="en">', "<head>", '<meta charset="utf-8">',
           '<meta name="viewport" content="width=device-width, initial-scale=1">',
           '<meta name="color-scheme" content="light dark">',
           "<title>Keepout results</title>", f"<style>{CSS}</style>", "</head>", "<body>", "<main>",
           "<h1>Keepout results</h1>",
           f'<p class="lede">Keepout results — {model["run_count"]} runs, generated from {model["file_count"]} files. '
           f"{_e(SCOPE)}</p>",
           '<div class="wrap"><table>', "<thead><tr><th scope=\"col\">check</th>"]
    for column in cols:
        h = column["header"]
        note = (f'<span class="heldnote">{column["run"]["held_count"]} held for private vendor report</span>'
                if column["held"] else "")
        out.append(f'<th scope="col" title="{_e(column["run"].get("_file", ""))}">{_e(h["harness"])} '
                   f'{_e(h["version"])}<span>{_e(h["os"])}</span><span>{_e(h["date"])}</span>{note}</th>')
    out.append("</tr></thead><tbody>")
    out.append(f'<tr class="extra"><th scope="row">{_e(ROW_CONTROLS)}</th>'
               + "".join(_plain_cell(c["controls"]) for c in cols) + "</tr>")
    out.append(f'<tr class="extra"><th scope="row">{_e(ROW_OMISSION)}</th>'
               + "".join(_plain_cell(c["omission"]) for c in cols) + "</tr>")
    out.append(f'<tr class="extra"><th scope="row">{_e(ROW_STATUS)}</th>'
               + "".join(f'<td class="status">{_e(c["run"]["status"])}</td>' for c in cols) + "</tr>")
    for row in model["rows"]:
        out.append(f'<tr><th scope="row">{_e(row)}</th>' + "".join(_html_cell(model, c, row) for c in cols) + "</tr>")
    out.append("</tbody></table></div>")
    out.append("<h2>History</h2>")
    if model["history"]:
        out.append("<ul>")
        for run in model["history"]:
            out.append(f"<li><strong>{_e(run.get('_file', ''))}</strong> ({_e(_header_text({'header': _header(run)}))}): "
                       f"{_e(run['history_reason'])} Status: {_e(run['status'])}.</li>")
        out.append("</ul>")
    else:
        out.append("<p>No superseded or older runs.</p>")
    out.append(f'<p class="foot">{_e(SCOPE)} A run with any check held for private vendor review shows '
               "<em>held</em> in every denial cell, so the held check cannot be identified. "
               "Legacy runs are never shown as control-validated.</p>")
    out += ["</main>", "</body>", "</html>", ""]
    return "\n".join(out)


# ---------------------------------------------------------------- Markdown


def _md(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def render_markdown(model: dict) -> str:
    cols = model["columns"]
    lines = ["# Keepout results", "", SCOPE, "",
             f"Keepout results — {model['run_count']} runs, generated from {model['file_count']} files.", ""]
    lines.append("| check | " + " | ".join(_md(_header_text(c)) for c in cols) + " |")
    lines.append("| --- |" + " --- |" * len(cols))
    lines.append(f"| {ROW_CONTROLS} | " + " | ".join(_md(c["controls"]) for c in cols) + " |")
    lines.append(f"| {ROW_OMISSION} | " + " | ".join(_md(c["omission"]) for c in cols) + " |")
    lines.append(f"| {ROW_STATUS} | " + " | ".join(_md(c["run"]["status"]) for c in cols) + " |")
    for row in model["rows"]:
        lines.append(f"| {_md(row)} | " + " | ".join(_md(_cell_text(model, c, row)) for c in cols) + " |")
    lines += ["", "## Runs", ""]
    for column in cols:
        run = column["run"]
        parts = [f"`{_md(run.get('_file', ''))}`", f"harness: {_md(run['harness'])}", f"CLI: {_md(run['cli_version'])}",
                 f"OS: {_md(run['os'])}", f"date: {_md(run['date'])}", f"status: {_md(run['status'])}"]
        mode = (run.get("profile_receipt") or {}).get("generated_profile_network_mode")
        if mode:
            parts.append(f"generated network mode: {_md(mode)}")
        parts.append(f"held: {run['held_count']}")
        lines.append("- " + "; ".join(parts))
    lines += ["", "## Evidence", ""]
    for column in cols:
        run = column["run"]
        lines += ["<details>", f"<summary>{html.escape(_header_text(column))}</summary>", "",
                  "| check | verdict | classification | control evidence | sandbox evidence |",
                  "| --- | --- | --- | --- | --- |"]
        for check in run["checks"]:
            if check["classification"] in HELD:
                continue
            if column["held"] and model["expectations"].get(check["id"], check["expectation"]) in ("deny", "unknown"):
                continue
            cells = (check["id"], check["verdict"], check["classification"], check["control_evidence"],
                     check["sandbox_evidence"])
            lines.append("| " + " | ".join(_md(cell) for cell in cells) + " |")
        if column["held"]:
            lines += ["", f"{run['held_count']} checks held for private vendor report; "
                          "every denial result in this run is withheld until review."]
        lines += ["", "</details>", ""]
    lines += ["## History", ""]
    if model["history"]:
        for run in model["history"]:
            lines.append(f"- `{_md(run.get('_file', ''))}` ({_md(_header_text({'header': _header(run)}))}): "
                         f"{_md(run['history_reason'])} Status: {_md(run['status'])}.")
    else:
        lines.append("No superseded or older runs.")
    lines.append("")
    return "\n".join(lines)
