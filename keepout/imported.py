"""Run an existing Codex permission profile against disposable canaries.

`python3 -m keepout run --harness codex --config CONFIG --profile NAME`

Every configured path is remapped, as pure string work, into a fresh disposable root; Keepout never stats, reads or
writes the real path. The generated config carries only the profile's [permissions.*] chain. Controls come before
denials, exactly as in the policy runner: allowed actions must succeed inside the sandbox, every denial needs an
exposed unsandboxed control, and a run-wide omitted-rule check must show that a missing rule is detected.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import select
import shutil
import subprocess
import tempfile

from . import codexconfig as cc
from . import lint as lintmod
from .checks import HELD, WITHHELD, Check, Observation, evaluate, public_result
from .codex import LISTENER, PYTHON, PYTHON_READ, SHELL_READ, TCP, UNIX, WRITE, find_codex

# A FAIL whose (row kind, lint id) is listed here is a known configuration outcome, not a held finding. Each entry
# carries its measurement receipt. Changing this table needs a person's review: it decides what is published.
KNOWN_OUTCOMES: dict[tuple[str, str], str] = {
    ("minimal-tmp-exposure", "KO020"):
        "2026-10-03, codex-cli 0.156.1 macOS: with \":root\"=\"deny\" and \":minimal\"=\"read\", a canary under "
        "/private/tmp/koexp-*/protected was EXPOSED (also with -C in /private/var/folders and via /tmp/..); the same "
        "canary under /private/var/folders was BLOCKED; adding \"/private/tmp\"=\"deny\" made it BLOCKED. Binary "
        "string: 'macOS platform defaults included when a split filesystem policy requests `:minimal`'.",
    ("carve-out", "KO022"):
        "2026-10-03 O2: deny {R}/prot plus write {R}/prot/inner: inner read and write both succeeded while the "
        "parent file stayed BLOCKED (more specific rule wins).",
    ("extends-relax", "KO024"):
        "2026-10-03 C7: [permissions.p] denies {R}/protected; [permissions.c] extends p and sets it to read; "
        "`-P c` gave EXPOSED. C6 (no override) gave BLOCKED.",
    ("ignored-network-key", "KO011"):
        "2026-10-03: loopback TCP under `codex sandbox -P p` was BLOCKED for mode=\"full\", mode=\"limited\", "
        "enabled=false and no key; only enabled=true gave EXPOSED (:read-only and :workspace alike).",
    ("ignored-token", "KO013"):
        "2026-10-03: \":home\"=\"deny\" left a canary under the fake HOME EXPOSED with empty stderr under "
        "`codex sandbox`; `codex exec` warned 'Configured filesystem path `:home` is not recognized'.",
}
HONESTY = ("Findings and results apply to codex-cli 0.156.1 on this macOS machine; none is a vendor vulnerability "
           "claim. `:minimal`'s /private/tmp read is documented-by-design platform defaults, reported because it "
           "defeats a common :root-deny intent.")
MACHINE_TOKENS = {":root", ":minimal", ":slash_tmp"}
TMP_NOTE = "real path is under /private/tmp; remapped result does not reflect :minimal coverage"
INVALID_ROOT = "INVALID: disposable root inside a :minimal path"


class RemapError(ValueError):
    pass


def synth_glob(pattern: str, tag: str = "") -> str | None:
    """One concrete path matching a glob, or None when it has character classes."""
    if any(char in pattern for char in "[]{}"):
        return None
    return (pattern.replace("**", "\0").replace("*", f"keepout{tag}").replace("?", "k")
            .replace("\0", f"kd1{tag}/kd2"))


@dataclass
class Layout:
    """One disposable root: home/ (fake HOME), home/.codex (CODEX_HOME), tmp/ (TMPDIR), workspace/ (-C), abs/."""
    root: Path

    @property
    def home(self) -> Path:
        return self.root / "home"

    @property
    def codex_home(self) -> Path:
        return self.home / ".codex"

    @property
    def tmp(self) -> Path:
        return self.root / "tmp"

    @property
    def workspace(self) -> Path:
        return self.root / "workspace"

    def make(self) -> None:
        for folder in (self.codex_home, self.tmp, self.workspace, self.root / "abs"):
            self._mkdir(folder)

    def _mkdir(self, folder: Path) -> None:
        self.inside(folder)
        folder.mkdir(parents=True, exist_ok=True)

    def inside(self, path: Path) -> Path:
        if ".." in path.parts or not Path(os.path.normpath(path)).resolve().is_relative_to(self.root):
            raise RemapError(f"remapped path escapes the disposable root: {path}")
        return path

    def map_path(self, scope: str, path: str) -> Path | None:
        """Pure string remap of a configured path into this root. None for a machine-wide token."""
        if ".." in path.split("/"):
            raise RemapError(f"refusing to remap a path with '..': {path}")
        norm = cc.normalize(path) if scope in ("abs", "home", "workspace_roots") else path
        if scope == "abs":
            mapped = self.root / "abs" / norm.lstrip("/") if norm != "/" else self.root / "abs"
        elif scope == "home":
            mapped = self.home / norm[2:] if norm.startswith("~/") else self.home
        elif scope == "workspace_roots":
            mapped = self.workspace / norm
        elif path == ":tmpdir":
            mapped = self.tmp
        elif path == ":workspace_roots":
            mapped = self.workspace
        else:
            return None
        return self.inside(mapped)

    def config_key(self, scope: str, path: str) -> str:
        if scope == "abs":
            return str(self.map_path(scope, path))
        return path  # ~/x stays ~/x (fake HOME), tokens and :workspace_roots children stay as written

    def plant(self, path: Path, value: str) -> None:
        self.inside(path)
        self._mkdir(path.parent)
        if path.is_symlink():
            raise RemapError(f"refusing to follow a link at {path}")
        path.write_text(value)


def build_config(cfg: cc.CodexConfig, resolved: cc.ResolvedProfile, layout: Layout,
                 omit: tuple[str, str] | None = None) -> tuple[str, list[str], list[str]]:
    """Return (config text, dropped keys, verbatim denies). Carries only the [permissions.*] chain."""
    dropped = sorted(key for key in cfg.data if key not in ("permissions", "default_permissions"))
    permissions: dict = {}
    verbatim: list[str] = []
    for name in resolved.chain:
        if name in cc.BUILTINS:
            continue
        table = cfg.data["permissions"][name]
        out: dict = {}
        for key, value in table.items():
            if key == "filesystem" and isinstance(value, dict):
                fs: dict = {}
                for path, access in value.items():
                    if omit == (name, path):
                        continue
                    scope = cc.scope_of(path)
                    if isinstance(access, dict) or scope in ("token", "relative"):
                        fs[path] = access
                        continue
                    fs[layout.config_key(scope, path)] = access
                    if scope == "abs" and access == "deny" and cc.normalize(path) == "/private/tmp":
                        fs["/private/tmp"] = "deny"  # a deny restricts only; kept so :minimal coverage is measured
                        verbatim.append("/private/tmp")
                out[key] = fs
            elif key == "workspace_roots" and isinstance(value, list):
                out[key] = [str(layout.map_path("abs", item)) if isinstance(item, str) and item.startswith("/")
                            else item for item in value]
            else:
                try:
                    cc.dumps({key: value})
                except TypeError:
                    dropped.append(f"permissions.{name}.{key}")
                    continue
                out[key] = value
        permissions[name] = out
    text = cc.dumps({"default_permissions": resolved.name, "permissions": permissions})
    return text, dropped, verbatim


@dataclass
class Probe:
    kind: str  # shell_read | python_read | write_new | overwrite | write_at | tcp | unix | echo
    target: Path | None = None
    layout: str = "dir"
    control_target: Path | None = None
    canary: Path | None = None  # replanted before each evaluation


@dataclass
class Row:
    id: str
    kind: str
    description: str
    expectation: str  # allow | deny | intent_allow
    probe: Probe | None = None
    entry: str = ""
    lint_id: str | None = None
    untestable_reason: str = ""
    note: str = ""
    omission: tuple[str, str] | None = None  # (profile, path) dropped for the per-rule omission rerun
    result: dict = field(default_factory=dict)


class ImportedRunner:
    def __init__(self, cfg: cc.CodexConfig, profile: str, cli: str | None = None):
        self.cfg = cfg
        self.resolved = cc.resolve(cfg, profile)
        self.profile = profile
        self.cli = cli or find_codex()
        self.temp: tempfile.TemporaryDirectory[str] | None = None
        self.min_dir: str | None = None
        self.listeners: list[subprocess.Popen[str]] = []
        self.tcp_port = ""
        self.unix_path: Path | None = None
        self.rows: list[Row] = []
        self.counter = 0

    # ---- set-up ----

    def __enter__(self) -> "ImportedRunner":
        self.temp = tempfile.TemporaryDirectory(prefix="keepout-imp-", dir=tempfile.gettempdir())
        self.root = Path(self.temp.name).resolve()
        self.invalid_root = str(self.root).startswith("/private/tmp") or str(self.root).startswith("/tmp")
        self.layouts = {"dir": Layout(self.root / "dir-shape"), "file": Layout(self.root / "file-shape")}
        self.marker = "keepout-" + secrets.token_hex(24)
        self.findings = lintmod.lint(self.cfg, self.profile)
        self.fired = {item["id"] for item in self.findings}
        if self.invalid_root:
            return self
        try:
            for layout in self.layouts.values():
                layout.make()
            self.rows = self.plan()
            self.configs: dict[str, str] = {}
            for name, layout in self.layouts.items():
                text, self.dropped, self.verbatim = build_config(self.cfg, self.resolved, layout)
                (layout.codex_home / "config.toml").write_text(text)
                self.configs[name] = text
        except BaseException:
            self.__exit__()
            raise
        return self

    def __exit__(self, *_: object) -> None:
        for child in self.listeners:
            if child.poll() is None:
                child.terminate()  # exact Popen PID only
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=3)
            for stream in (child.stdout, child.stderr):
                if stream:
                    stream.close()
        if self.min_dir:
            shutil.rmtree(self.min_dir, ignore_errors=True)  # the folder Keepout itself created by mkdtemp
        if self.temp:
            self.temp.cleanup()

    def env(self, layout: Layout, codex_home: Path | None = None) -> dict[str, str]:
        return {"PATH": "/usr/bin:/bin:/opt/homebrew/bin", "HOME": str(layout.home),
                "CODEX_HOME": str(codex_home or layout.codex_home), "TMPDIR": str(layout.tmp),
                "LANG": "en_US.UTF-8"}

    # ---- the plan (pure apart from planting canaries) ----

    def plan(self) -> list[Row]:
        rows: list[Row] = []
        res = self.resolved
        dir_l, file_l = self.layouts["dir"], self.layouts["file"]
        entries = [entry for entry in res.filesystem if entry.access != "table"]
        rows.append(Row("allowed:echo", "allowed", "Run /bin/echo in workspace/", "allow", Probe("echo")))
        for entry in entries:
            if entry.access in ("read", "write") and entry.scope != "token" and not cc.is_glob(entry.path):
                mapped = dir_l.map_path(entry.scope, entry.path)
                if entry.access == "write":
                    dir_l._mkdir(mapped)
                    rows.append(Row(f"allowed:write:{entry.label}", "allowed", f"Write a new file in {entry.label}",
                                    "allow", Probe("write_new", mapped), entry.label))
                else:
                    canary = mapped / "keepout-canary"
                    rows.append(Row(f"allowed:read:{entry.label}", "allowed", f"Read a canary in {entry.label}",
                                    "allow", Probe("shell_read", canary, canary=canary), entry.label))
                    rows.append(Row(f"read-only:{entry.label}:write-new", "read-only",
                                    f"Write a new file in read-only {entry.label}", "deny",
                                    Probe("write_new", mapped), entry.label))
        for entry in entries:
            if entry.access not in ("deny", "none"):
                continue
            if entry.scope == "token" and (entry.path in MACHINE_TOKENS or entry.path not in cc.TOKENS):
                reason = ("machine-wide token; Keepout never plants in real system paths"
                          if entry.path in MACHINE_TOKENS else "unknown token; Codex 0.156.1 ignores it (KO013)")
                rows.append(Row(f"token:{entry.path}", "token", f"{entry.path} = {entry.access}", "deny",
                                entry=entry.path, untestable_reason=reason,
                                lint_id="KO013" if entry.path not in cc.TOKENS else None))
                if entry.path not in cc.TOKENS and "home" in entry.path:
                    canary = dir_l.home / "keepout-ignored-token-canary"
                    rows.append(Row(f"ignored-token:{entry.path}:shell-read", "ignored-token",
                                    f"Read a canary in the fake HOME that {entry.path} = deny names", "deny",
                                    Probe("shell_read", canary, canary=canary), entry.path, "KO013"))
                continue
            if cc.is_glob(entry.path):
                rows.extend(self._glob_rows(entry, entries))
                continue
            rows.extend(self._deny_rows(entry, entries))
        rows.extend(self._override_rows())
        rows.extend(self._carve_out_rows(entries))
        rows.extend(self._network_rows())
        if any(item in ("read", "write") for item in res.access(":minimal")):
            self.min_dir = tempfile.mkdtemp(prefix="keepout-min-", dir="/private/tmp")
            canary = Path(self.min_dir) / "secret.txt"
            lint_id = "KO020" if lintmod.minimal_tmp_exposed(res) else None
            for kind in ("shell_read", "python_read"):
                rows.append(Row(f"minimal-tmp-exposure:{kind.replace('_', '-')}", "minimal-tmp-exposure",
                                "Read a Keepout canary in a fresh /private/tmp folder under :minimal", "deny",
                                Probe(kind, canary, canary=canary), ":minimal", lint_id))
        return rows

    def _note(self, entry: cc.Entry) -> str:
        if entry.scope == "abs" and cc.covers("/private/tmp", cc.normalize(entry.path)):
            return TMP_NOTE
        return ""

    def _deny_rows(self, entry: cc.Entry, entries: list[cc.Entry]) -> list[Row]:
        rows: list[Row] = []
        label = entry.label
        lint_id = "KO030" if entry.scope in ("abs", "home") and cc.normalize(entry.path) != entry.path else None
        omission = (entry.profile, entry.path) if entry.scope != "workspace_roots" else None
        dir_l, file_l = self.layouts["dir"], self.layouts["file"]
        mapped = dir_l.map_path(entry.scope, entry.path)
        canary = mapped / "keepout-canary"
        probes = [("shell-read", Probe("shell_read", canary, canary=canary)),
                  ("python-read", Probe("python_read", canary, canary=canary)),
                  ("write-new", Probe("write_new", mapped))]
        for name, probe in probes:
            row = Row(f"deny:{label}[dir]:{name}", "deny", f"{name} of a canary folder under denied {label}", "deny",
                      probe, label, lint_id, note=self._note(entry), omission=omission if name == "shell-read" else None)
            if name == "write-new" and entry.access == "none":
                row.untestable_reason = "value `none`: write semantics undocumented"
            rows.append(row)
        nested = [other for other in entries if other is not entry and other.scope == entry.scope
                  and other.scope != "token" and cc.covers(cc.normalize(entry.path), cc.normalize(other.path))
                  and cc.normalize(other.path) != cc.normalize(entry.path)]
        file_reason = ("token maps to a folder" if entry.scope == "token" else
                       "other entries sit inside this path; it cannot be a file" if nested else "")
        file_path = None if file_reason else file_l.map_path(entry.scope, entry.path)
        for name, kind in (("shell-read", "shell_read"), ("python-read", "python_read"), ("overwrite", "overwrite")):
            probe = Probe(kind, file_path, "file", canary=file_path) if file_path else None
            row = Row(f"deny:{label}[file]:{name}", "deny", f"{name} of {label} as a file", "deny", probe, label,
                      lint_id, file_reason, self._note(entry))
            if name == "overwrite" and entry.access == "none" and not file_reason:
                row.untestable_reason = "value `none`: write semantics undocumented"
            rows.append(row)
        return rows

    def _writable(self, path: Path, entries: list[cc.Entry]) -> bool:
        dir_l = self.layouts["dir"]
        for other in entries:
            if other.access != "write" or cc.is_glob(other.path) or other.path in MACHINE_TOKENS:
                continue
            if other.scope == "token" and other.path not in cc.TOKENS:
                continue
            mapped = dir_l.map_path(other.scope, other.path)
            if mapped is not None and path.is_relative_to(mapped):
                return True
        if self.resolved.base in (":workspace", ":danger-full-access"):
            return path.is_relative_to(dir_l.workspace) or path.is_relative_to(dir_l.tmp)
        return False

    def _glob_rows(self, entry: cc.Entry, entries: list[cc.Entry]) -> list[Row]:
        label = entry.label
        dir_l = self.layouts["dir"]
        planted = synth_glob(entry.path)
        if planted is None:
            reason = "character classes not synthesized"
            return [Row(f"glob:{label}:planted", "glob", f"glob {label}", "deny", entry=label, untestable_reason=reason),
                    Row(f"glob:{label}:created-in-sandbox", "glob", f"glob {label}", "deny", entry=label,
                        untestable_reason=reason)]
        target = dir_l.map_path(entry.scope, planted)
        rows = [Row(f"glob:{label}:planted:shell-read", "glob", f"Read a planted file matching {label}", "deny",
                    Probe("shell_read", target, canary=target), label, note=self._note(entry))]
        sandbox_path = dir_l.map_path(entry.scope, synth_glob(entry.path, "s"))
        control_path = dir_l.map_path(entry.scope, synth_glob(entry.path, "c"))
        if self._writable(sandbox_path, entries):
            for path in (sandbox_path, control_path):
                dir_l._mkdir(path.parent)
            rows.append(Row(f"glob:{label}:created-in-sandbox", "glob",
                            f"Create a file matching {label} inside the sandbox", "deny",
                            Probe("write_at", sandbox_path, control_target=control_path), label))
        else:
            rows.append(Row(f"glob:{label}:created-in-sandbox", "glob", f"Create a file matching {label}", "deny",
                            entry=label, untestable_reason="no writable ancestor for a file created in the sandbox"))
        return rows

    def _override_rows(self) -> list[Row]:
        rows = []
        dir_l = self.layouts["dir"]
        for parent, child in self.resolved.overridden:
            rows.append(Row(f"overridden:{parent.profile}:{parent.label}", "overridden",
                            f"{parent.profile}'s {parent.label} = {parent.access}", "deny" if parent.access == "deny"
                            else "allow", entry=parent.label,
                            untestable_reason="replaced by child profile entry, see KO024"))
            if parent.access in ("deny", "none") and child.access in ("read", "write") and parent.scope != "token":
                canary = dir_l.map_path(parent.scope, parent.path) / "keepout-canary"
                rows.append(Row(f"extends-relax:{parent.label}:shell-read", "extends-relax",
                                f"Read a canary under {parent.label}, denied by parent {parent.profile} and set to "
                                f"{child.access} by child {child.profile}", "deny",
                                Probe("shell_read", canary, canary=canary), parent.label, "KO024"))
        return rows

    def _carve_out_rows(self, entries: list[cc.Entry]) -> list[Row]:
        rows = []
        dir_l = self.layouts["dir"]
        denies = [e for e in entries if e.access in ("deny", "none") and e.scope != "token" and not cc.is_glob(e.path)]
        for deny in denies:
            for allow in entries:
                if allow.access not in ("read", "write") or allow.scope != deny.scope or cc.is_glob(allow.path):
                    continue
                outer, inner = cc.normalize(deny.path), cc.normalize(allow.path)
                if inner == outer or not cc.covers(outer, inner):
                    continue
                mapped = dir_l.map_path(allow.scope, allow.path)
                if allow.access == "write":
                    probe, name = Probe("write_new", mapped), "write-new"
                else:
                    canary = mapped / "keepout-canary"
                    probe, name = Probe("shell_read", canary, canary=canary), "shell-read"
                rows.append(Row(f"carve-out:{allow.label}:{name}", "carve-out",
                                f"{name} in {allow.label} ({allow.access}) inside denied {deny.label}", "deny",
                                probe, allow.label, "KO022"))
        return rows

    def _network_rows(self) -> list[Row]:
        net = self.resolved.network
        enabled = net.get("enabled") is True
        expectation = "allow" if enabled else "deny"
        rows = [Row("network:tcp-loopback", "network", "Connect to an owned 127.0.0.1 listener", expectation,
                    Probe("tcp")),
                Row("network:unix-socket", "network", "Connect to an owned Unix socket", expectation, Probe("unix"))]
        if "mode" in net:
            intent = "intent_allow" if net["mode"] in ("full", "enabled", "on", "allow") else "deny"
            rows.append(Row("ignored-network-key:tcp-loopback", "ignored-network-key",
                            f"network.mode = {json.dumps(net['mode'])}: does loopback follow the written intent?",
                            intent, Probe("tcp"), "network.mode", "KO011"))
        if "domains" in net:
            rows.append(Row("network:domains", "network", "domains rules", "deny", entry="network.domains",
                            untestable_reason="off-host routes need external_routes opt-in"))
        if "unix_sockets" in net:
            rows.append(Row("network:unix_sockets", "network", "unix_sockets rules", "deny",
                            entry="network.unix_sockets", untestable_reason="not remapped in v0.2"))
        return rows

    # ---- execution ----

    def _start_listener(self, kind: str) -> str:
        layout = self.layouts["dir"]
        address = str(layout.root / "local.sock") if kind == "unix" else "unused"
        child = subprocess.Popen([PYTHON, "-B", "-c", LISTENER, kind, address], cwd=layout.workspace,
                                 env=self.env(layout), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.listeners.append(child)
        assert child.stdout is not None
        ready, _, _ = select.select([child.stdout], [], [], 5)
        line = child.stdout.readline().strip() if ready else ""
        if not line or (kind == "unix" and line != "READY") or (kind == "tcp" and not line.isdigit()):
            return ""
        return line

    def _argv(self, probe: Probe, sandboxed: bool) -> list[str]:
        if probe.kind == "echo":
            return ["/bin/echo", "EXPOSED"]
        if probe.kind == "shell_read":
            return ["/bin/sh", "-c", SHELL_READ, "sh", str(probe.target), self.marker]
        if probe.kind == "python_read":
            return [PYTHON, "-B", "-c", PYTHON_READ, str(probe.target), self.marker]
        if probe.kind == "write_new":
            self.counter += 1
            name = f"{'sandbox' if sandboxed else 'control'}-write-{self.counter}"
            return [PYTHON, "-B", "-c", WRITE, str(Path(probe.target) / name)]
        if probe.kind == "overwrite":
            return [PYTHON, "-B", "-c", WRITE, str(probe.target)]
        if probe.kind == "write_at":
            target = probe.target if sandboxed else probe.control_target
            return [PYTHON, "-B", "-c", WRITE, str(target)]
        if probe.kind == "tcp":
            return [PYTHON, "-B", "-c", TCP, self.tcp_port or "0"]
        if probe.kind == "unix":
            return [PYTHON, "-B", "-c", UNIX, str(self.unix_path)]
        raise ValueError(f"unknown probe kind: {probe.kind}")

    def observe(self, probe: Probe, sandboxed: bool, codex_home: Path | None = None,
                extra: tuple[str, ...] = ()) -> Observation:
        layout = self.layouts[probe.layout]
        if probe.kind == "tcp" and not self.tcp_port:
            self.tcp_port = self._start_listener("tcp")
        if probe.kind == "unix" and self.unix_path is None and self._start_listener("unix"):
            self.unix_path = self.layouts["dir"].root / "local.sock"
        if (probe.kind == "tcp" and not self.tcp_port) or (probe.kind == "unix" and not self.unix_path):
            return Observation("ERROR", "owned listener failed to start")
        command = self._argv(probe, sandboxed)
        if sandboxed:
            command = [self.cli, "sandbox", "-C", str(layout.workspace), "-P", self.profile, *extra, "--", *command]
        try:
            result = subprocess.run(command, cwd=layout.workspace, env=self.env(layout, codex_home),
                                    capture_output=True, text=True, timeout=12)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return Observation("ERROR", self.clean(f"probe could not complete: {type(exc).__name__}"))
        return classify(result.returncode, result.stdout, result.stderr, self.clean)

    def evaluate_row(self, row: Row) -> dict:
        check = Check(row.id, row.description, row.kind, row.entry,
                      "allow" if row.expectation == "allow" else "deny", row.untestable_reason)
        if row.probe and row.probe.canary is not None and not row.untestable_reason:
            self.plant(row.probe)
        runner = self

        class Adapter:
            def run(self, _check: Check, sandboxed: bool) -> Observation:
                return runner.observe(row.probe, sandboxed)

        result = evaluate(check, Adapter())
        if row.expectation == "intent_allow":
            # The written intent is "network on": BLOCKED means the key did nothing.
            result["expectation"] = "intent_allow"
            if result["verdict"] in ("PASS", "FAIL"):
                result["verdict"] = "FAIL" if result["verdict"] == "PASS" else "PASS"
                result["classification"] = "configuration_outcome"
                result["sandbox_evidence"] += "; written intent was allow"
        return result

    def plant(self, probe: Probe) -> None:
        if probe.canary.is_relative_to(self.root):
            self.layouts[probe.layout].plant(probe.canary, self.marker)
        else:
            _plant_owned(probe.canary, self.marker, self.min_dir)

    def run(self) -> dict:
        if self.invalid_root:
            return self.report([], {"verdict": "INVALID", "evidence": INVALID_ROOT}, status=INVALID_ROOT)
        results = []
        for row in self.rows:
            result = self.evaluate_row(row)
            result.update(kind=row.kind, entry=row.entry, lint_id=row.lint_id, note=row.note,
                          tested=not bool(row.untestable_reason), untestable_reason=row.untestable_reason)
            row.result = result
            results.append(result)
        self.per_rule_omission()
        log_denials = self.log_denials()
        omission = run_wide_omission(self.cli)
        status = self.apply_controls(results, omission)
        self.classify_fails(results)
        report = self.report(results, omission, status)
        report["log_denials"] = log_denials
        return report

    def per_rule_omission(self) -> None:
        dir_l = self.layouts["dir"]
        for index, row in enumerate(self.rows):
            if not row.omission or row.result.get("verdict") != "PASS":
                if row.omission:
                    row.result["load_bearing"] = None
                continue
            home = dir_l.root / f"codex-omit-{index}"
            dir_l._mkdir(home)
            text, _, _ = build_config(self.cfg, self.resolved, dir_l, omit=row.omission)
            (home / "config.toml").write_text(text)
            if row.probe.canary is not None:
                self.plant(row.probe)
            observed = self.observe(row.probe, True, codex_home=home)
            row.result["load_bearing"] = observed.state == "EXPOSED"
            if observed.state == "BLOCKED":
                row.result["note"] = "; ".join(filter(None, [row.result.get("note"),
                                               "also blocked without this rule (covered by base/broader deny)"]))
            elif observed.state != "EXPOSED":
                row.result["load_bearing"] = None
                row.result["note"] = "; ".join(filter(None, [row.result.get("note"),
                                               "omission rerun inconclusive: " + observed.evidence]))

    def log_denials(self) -> dict:
        row = next((r for r in self.rows if r.kind == "deny" and r.probe and r.result.get("verdict") == "PASS"), None)
        if row is None:
            return {"verdict": "UNMEASURED", "evidence": "no measured denial to capture"}
        if row.probe.canary is not None:
            self.plant(row.probe)
        layout = self.layouts[row.probe.layout]
        command = [self.cli, "sandbox", "-C", str(layout.workspace), "-P", self.profile, "--log-denials", "--",
                   *self._argv(row.probe, True)]
        parsed: dict = {}
        for attempt in range(1, 4):  # `log stream` can attach late and miss a short command; retry the same probe
            try:
                result = subprocess.run(command, cwd=layout.workspace, env=self.env(layout), capture_output=True,
                                        text=True, timeout=20)
            except (OSError, subprocess.TimeoutExpired) as exc:
                return {"verdict": "UNMEASURED", "evidence": f"--log-denials could not complete: {type(exc).__name__}"}
            parsed = parse_denials(row.id, self.clean((result.stdout + "\n" + result.stderr).strip()))
            parsed["attempts"] = attempt
            if parsed["verdict"] == "CAPTURED":
                break
        return parsed

    def apply_controls(self, results: list[dict], omission: dict) -> str:
        allowed = [item for item in results if item["kind"] == "allowed"]
        failed = [item["id"] for item in allowed if item["verdict"] != "PASS"]
        reason = ""
        if failed:
            reason = "sandbox blocked allowed actions; denials prove nothing (" + ", ".join(failed) + ")"
            if "allowed:echo" in failed:
                reason += "; /bin/echo itself failed, see KO021"
        elif omission.get("verdict") != "PASS":
            reason = "omitted-rule control failed; denials prove nothing"
        if reason:
            for item in results:
                if item["expectation"] in ("deny", "intent_allow") and item["tested"]:
                    item["verdict"] = "INVALID"
                    item["sandbox_evidence"] = reason
            return "INVALID: " + reason
        return "controls passed"

    def classify_fails(self, results: list[dict]) -> None:
        for item in results:
            if item["verdict"] != "FAIL":
                continue
            key = (item["kind"], item.get("lint_id"))
            if key in KNOWN_OUTCOMES and item.get("lint_id") in self.fired:
                item["classification"] = "configuration_outcome"
                item["known_outcome"] = KNOWN_OUTCOMES[key]
            else:
                item["classification"] = "pending_review"

    def report(self, results: list[dict], omission: dict, status: str) -> dict:
        dir_l = self.layouts["dir"]
        remap = []
        for entry in self.resolved.filesystem:
            if entry.access == "table":
                continue
            try:
                mapped = dir_l.map_path(entry.scope, entry.path)
            except RemapError as exc:
                mapped = None
                remap.append({"original": entry.label, "profile": entry.profile, "mapped": f"refused: {exc}"})
                continue
            remap.append({"original": entry.label, "profile": entry.profile, "access": entry.access,
                          "mapped": self.clean(str(mapped)) if mapped else "not remapped (token)"})
        counts = {name: sum(item["verdict"] == name for item in results)
                  for name in ("PASS", "FAIL", "INVALID", "UNMEASURED")}
        counts["tested"] = sum(item["tested"] for item in results)
        counts["untestable"] = sum(not item["tested"] for item in results)
        return {
            "harness": "codex sandbox imported permission profile",
            "cli_version": self.version(),
            "os": platform.platform(),
            "date": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "config": {"file": Path(self.cfg.path).name, "sha256": self.cfg.sha256,
                       "fixture_placeholder": cc.FIXTURE_ROOT if self.cfg.placeholder else None},
            "profile": self.profile,
            "extends_chain": self.resolved.chain,
            "remap": remap,
            "dropped_top_level_keys": getattr(self, "dropped", []),
            "verbatim_denies": getattr(self, "verbatim", []),
            "generated_config": self.clean(getattr(self, "configs", {}).get("dir", "")),
            "lint": self.findings,
            "rule_omission": omission,
            "status": status,
            "counts": counts,
            "honesty": HONESTY,
            "checks": results,
        }

    def version(self) -> str:
        try:
            result = subprocess.run([self.cli, "--version"], capture_output=True, text=True, timeout=10,
                                    env={"PATH": "/usr/bin:/bin", "HOME": str(self.root)})
            return result.stdout.strip() or "unknown"
        except (OSError, subprocess.TimeoutExpired):
            return "unknown"

    def clean(self, value: str) -> str:
        value = value.replace(self.marker, "<redacted>").replace(str(self.root), "<temp>")
        if self.min_dir:
            value = value.replace(self.min_dir, "/private/tmp/<keepout-min>")
        return value.replace(str(Path.home()), "~")


def _plant_owned(path: Path, value: str, owned: str | None) -> None:
    """Plant only inside the /private/tmp folder Keepout itself made with mkdtemp."""
    if not owned or not path.is_relative_to(owned) or path.is_symlink():
        raise RemapError(f"refusing to plant outside Keepout's own folder: {path}")
    path.write_text(value)


def classify(returncode: int, stdout: str, stderr: str, clean=lambda value: value) -> Observation:
    stdout, stderr = stdout.strip(), stderr.strip()
    if returncode == 0 and stdout == "EXPOSED":
        state = "EXPOSED"
    elif returncode == 0 and stdout == "BLOCKED":
        state = "BLOCKED"
    elif returncode == 20 and ("Operation not permitted" in stderr or "Permission denied" in stderr):
        state = "BLOCKED"
    else:
        state = "ERROR"
    return Observation(state, clean(f"exit {returncode}; stdout={stdout[:100]!r}; stderr={stderr[:180]!r}"))


def parse_denials(row_id: str, output: str) -> dict:
    """Keep Seatbelt's own denial lines for the probe's target (the canary path is already redacted to <temp>)."""
    head, marker, section = output.partition("=== Sandbox denials ===")
    lines = [line.strip() for line in section.splitlines() if line.strip()]
    target = [line for line in lines if "<temp>" in line and ("file-read" in line or "file-write" in line)]
    if not marker:
        return {"verdict": "UNMEASURED", "row": row_id,
                "evidence": "no denial section printed (log stream may need privileges): " + output[:300]}
    if not target:
        return {"verdict": "UNMEASURED", "row": row_id, "evidence": "denial section named no Keepout path; "
                f"{len(lines)} other denial lines (system probes)"}
    return {"verdict": "CAPTURED", "row": row_id, "evidence": "\n".join(dict.fromkeys(target))[:1200],
            "other_denial_lines": len(lines) - len(target)}


def run_wide_omission(cli: str) -> dict:
    """Keepout's bundled generated profile with one deny omitted must show exposure on this CLI and machine."""
    from .codex import CodexRunner
    from .policy import load_policy
    policy = load_policy(Path(__file__).resolve().parents[1] / "policy.toml")
    try:
        with CodexRunner(policy, cli) as runner:
            return runner.rule_omission()
    except Exception as exc:  # the control itself could not run: denials prove nothing
        return {"verdict": "INVALID", "evidence": f"run-wide omitted-rule control could not run: {type(exc).__name__}"}


# ---- publication boundary and rendering ----

def _short(path: str) -> str:
    """Keep the last two components: /.../a/b, ~/.../a/b, :token/.../a/b."""
    parts = path.split("/")
    rest = [part for part in parts[1:] if part]
    if len(rest) <= 2:
        return path
    return "/".join([parts[0], "...", *rest[-2:]])


def public_report(report: dict) -> dict:
    """Held rows are withheld; original config paths shrink to their last two components."""
    out = json.loads(json.dumps(report))
    originals = sorted({item["original"] for item in out.get("remap", [])}, key=len, reverse=True)
    normalized = sorted({cc.normalize(item) for item in originals if item.startswith(("/", "~"))}, key=len,
                        reverse=True)

    def shrink(value: str) -> str:
        for original in [*originals, *normalized]:
            value = value.replace(original, _short(original))
        return value

    for item in out.get("remap", []):
        item["original"] = _short(item["original"])
        item["mapped"] = shrink(item["mapped"])
    out["generated_config"] = shrink(out.get("generated_config", ""))
    checks = []
    for item in out.get("checks", []):
        safe = public_result(item)
        if safe.get("classification") in HELD:
            for key in ("entry", "note", "known_outcome"):
                if key in safe:
                    safe[key] = WITHHELD
        else:
            safe = {key: shrink(value) if isinstance(value, str) else value for key, value in safe.items()}
        checks.append(safe)
    out["checks"] = checks
    for item in out.get("lint", []):
        item["file"] = Path(str(item.get("file") or "")).name  # never the local folder layout
        for key in ("message", "path"):
            if isinstance(item.get(key), str):
                item[key] = shrink(item[key])
    return out


def markdown(report: dict) -> str:
    report = public_report(report)
    counts = report["counts"]
    lines = [
        "# Keepout result: imported Codex profile",
        "",
        f"- Harness: `{report['harness']}`",
        f"- CLI: `{report['cli_version']}`",
        f"- OS: `{report['os']}`",
        f"- Run time (UTC): `{report['date']}`",
        f"- Config: `{report['config']['file']}` sha256 `{report['config']['sha256']}`"
        + (f" (fixture: `{{R}}` read as `{report['config']['fixture_placeholder']}`)"
           if report["config"].get("fixture_placeholder") else ""),
        f"- Profile: `{report['profile']}`; extends chain: {' -> '.join('`' + item + '`' for item in report['extends_chain'])}",
        f"- Summary: {report['status']}; tested {counts['tested']}, untestable {counts['untestable']}; "
        f"PASS {counts['PASS']}, FAIL {counts['FAIL']}, INVALID {counts['INVALID']}, UNMEASURED {counts['UNMEASURED']}",
        f"- Run-wide omitted-rule control: {report['rule_omission'].get('verdict')}",
        f"- Seatbelt denial log (`--log-denials`, first denial probe): "
        f"{report.get('log_denials', {}).get('verdict', 'UNMEASURED')}: "
        f"`{report.get('log_denials', {}).get('evidence', '').replace(chr(10), '; ').replace('`', '')}`",
        f"- Dropped top-level keys (not carried into the generated config): "
        f"{', '.join('`' + key + '`' for key in report['dropped_top_level_keys']) or 'none'}",
        "",
        HONESTY,
        "",
        "Allowed actions run inside the sandbox first; every denial also needs an exposed unsandboxed control. If an "
        "allowed action fails, or the omitted-rule control cannot show exposure, every denial is INVALID.",
        "",
        "## Remap (config path -> disposable path)",
        "",
        "| Profile | Config path | Access | Disposable path |",
        "| --- | --- | --- | --- |",
    ]
    for item in report["remap"]:
        lines.append(_cells((item.get("profile", ""), item["original"], item.get("access", ""), item["mapped"])))
    lines += ["", "## Lint findings for this profile", ""]
    lines += [f"- {item['id']} {item['severity']}: {item['message']}" for item in report["lint"]] or ["- none"]
    lines += ["", "## Generated config (temporary paths redacted)", "", "```toml",
              report["generated_config"].rstrip(), "```", "",
              "| Row | Verdict | Classification | Lint | Load-bearing | Control evidence | Sandbox evidence | Note |",
              "| --- | --- | --- | --- | --- | --- | --- | --- |"]
    for item in report["checks"]:
        note = item.get("note") or ""
        lines.append(_cells((item["id"], item["verdict"], item["classification"], item.get("lint_id") or "",
                             "" if item.get("load_bearing") is None else str(item["load_bearing"]).lower(),
                             item["control_evidence"], item["sandbox_evidence"], note)))
    known = [item for item in report["checks"] if item.get("known_outcome")]
    if known:
        lines += ["", "## Known configuration outcomes (measurement receipts)", ""]
        lines += [f"- `{item['id']}` ({item['lint_id']}): {item['known_outcome']}" for item in known]
    return "\n".join(lines) + "\n"


def _cells(cells: tuple) -> str:
    return "| " + " | ".join(str(cell).replace("|", "\\|").replace("\n", " ") for cell in cells) + " |"


def write_report(report: dict, json_path: str | None, md_path: str | None) -> None:
    if json_path:
        path = Path(json_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(public_report(report), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if md_path:
        path = Path(md_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(markdown(report), encoding="utf-8")


def exit_code(report: dict) -> int:
    return 1 if report["counts"]["FAIL"] or report["counts"]["INVALID"] or report["status"] != "controls passed" else 0
