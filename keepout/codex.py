"""Codex CLI probes. Every path and credential value here is disposable."""

from __future__ import annotations

import json
import os
from pathlib import Path
import select
import secrets
import shutil
import subprocess
import sys
import tempfile
import tomllib

from .checks import Check, Observation
from .policy import Policy


PYTHON = sys.executable
SHELL_READ = 'value=$(/bin/cat "$1") || exit 20; [ "$value" = "$2" ] && echo EXPOSED || echo MISMATCH'
PYTHON_READ = (
    "import pathlib,sys; "
    "p=pathlib.Path(sys.argv[1]); expected=sys.argv[2]; "
    "\ntry: value=p.read_text()"
    "\nexcept PermissionError: print('BLOCKED'); sys.exit(0)"
    "\nexcept OSError as exc: print('ERROR:'+type(exc).__name__); sys.exit(3)"
    "\nprint('EXPOSED' if value == expected else 'MISMATCH')"
)
WRITE = (
    "import pathlib,sys; p=pathlib.Path(sys.argv[1]); "
    "\ntry: p.write_text('keepout-probe')"
    "\nexcept PermissionError: print('BLOCKED'); sys.exit(0)"
    "\nexcept OSError as exc: print('ERROR:'+type(exc).__name__); sys.exit(3)"
    "\nelse: print('EXPOSED')"
)
TCP = (
    "import socket,sys; "
    "\ntry: s=socket.create_connection(('127.0.0.1',int(sys.argv[1])),timeout=2)"
    "\nexcept PermissionError: print('BLOCKED'); sys.exit(0)"
    "\nexcept OSError as exc: print('ERROR:'+type(exc).__name__); sys.exit(3)"
    "\nelse: s.close(); print('EXPOSED')"
)
UNIX = (
    "import socket,sys; s=socket.socket(socket.AF_UNIX); "
    "\ntry: s.connect(sys.argv[1])"
    "\nexcept PermissionError: print('BLOCKED'); sys.exit(0)"
    "\nexcept OSError as exc: print('ERROR:'+type(exc).__name__); sys.exit(3)"
    "\nelse: s.close(); print('EXPOSED')"
)
ENV = (
    "import os,sys; print('EXPOSED' if os.environ.get('KEEPOUT_FAKE_TOKEN') == sys.argv[1] "
    "else 'BLOCKED')"
)
DNS = (
    "import socket,sys; "
    "\ntry: socket.getaddrinfo('example.com',443)"
    "\nexcept PermissionError: print('BLOCKED'); sys.exit(0)"
    "\nexcept OSError as exc: print('ERROR:'+type(exc).__name__); sys.exit(3)"
    "\nelse: print('EXPOSED')"
)
OFFHOST = (
    "import socket,sys; "
    "\ntry: s=socket.create_connection(('1.1.1.1',443),timeout=2)"
    "\nexcept PermissionError: print('BLOCKED'); sys.exit(0)"
    "\nexcept OSError as exc: print('ERROR:'+type(exc).__name__); sys.exit(3)"
    "\nelse: s.close(); print('EXPOSED')"
)
LISTENER = (
    "import socket,sys; kind=sys.argv[1]; "
    "s=socket.socket(socket.AF_INET if kind=='tcp' else socket.AF_UNIX); "
    "s.bind(('127.0.0.1',0) if kind=='tcp' else sys.argv[2]); s.listen(8); "
    "print(s.getsockname()[1] if kind=='tcp' else 'READY',flush=True); "
    "\nwhile True: conn,_=s.accept(); conn.close()"
)


def find_codex() -> str:
    cli = shutil.which("codex") or "/opt/homebrew/bin/codex"
    if not Path(cli).is_file():
        raise FileNotFoundError("codex CLI was not found on PATH or at /opt/homebrew/bin/codex")
    return cli


class CodexRunner:
    def __init__(self, policy: Policy, cli: str | None = None):
        self.policy = policy
        self.cli = cli or find_codex()
        self.temp: tempfile.TemporaryDirectory[str] | None = None
        self.listeners: list[subprocess.Popen[str]] = []
        self.targets: dict[str, Path] = {}
        self.tcp_port: str | None = None
        self.unix_path: Path | None = None

    def __enter__(self) -> "CodexRunner":
        self.temp = tempfile.TemporaryDirectory(prefix="keepout-", dir="/private/tmp")
        self.root = Path(self.temp.name).resolve()
        self.home = self.root / "home"
        self.work = self.root / "work"
        self.codex_home = self.home / ".config" / "codex"
        for folder in (self.home, self.work, self.codex_home, self.root / "tmp", self.root / "outside"):
            folder.mkdir(parents=True, exist_ok=True)
        for item in self.policy.writable_paths:
            (self.root / item).mkdir(parents=True, exist_ok=True)
        self.marker = "keepout-" + secrets.token_hex(24)
        self.token = "fake-" + secrets.token_hex(24)
        self.env = {
            "PATH": "/usr/bin:/bin:/opt/homebrew/bin",
            "HOME": str(self.home),
            "CODEX_HOME": str(self.codex_home),
            "TMPDIR": str(self.root / "tmp"),
            "KEEPOUT_FAKE_TOKEN": self.token,
            "LANG": "en_US.UTF-8",
        }
        for item in self.policy.protected_paths:
            folder = self.root / item
            folder.mkdir(parents=True, exist_ok=True)
            name = {
                "home/.ssh": "id_test",
                "home/.config/codex": "settings.toml",
                "home/.config/secrets": "credentials",
            }.get(item, "marker.txt")
            target = folder / name
            target.write_text(self.marker)
            self.targets[item] = target
        (self.work / "allowed-canary").write_text(self.marker)
        (self.work / "protected-link").symlink_to(self.targets.get("home/.ssh", self.root / "missing"))
        self.profile = self._profile()
        self.profile_network = tomllib.loads("profile = " + self.profile)["profile"]["network"]["mode"]
        return self

    def _profile(self, omit: str | None = None) -> str:
        filesystem = {str(self.root / path): "deny" for path in self.policy.protected_paths if path != omit}
        filesystem.update({str(self.root / path): "write" for path in self.policy.writable_paths})
        entries = ", ".join(f"{json.dumps(key)} = {json.dumps(value)}" for key, value in filesystem.items())
        network_mode = "full" if self.policy.network else "limited"
        return f'{{ extends = ":read-only", network = {{ mode = "{network_mode}" }}, filesystem = {{ {entries} }} }}'

    def receipt(self) -> dict[str, object]:
        return {
            "config_overrides": ["permissions.keepout=" + self._clean(self.profile),
                                 "shell_environment_policy.inherit=none"],
            "environment_override_scope": "filtered-token only",
            "generated_profile_network_mode": self.profile_network,
            "codex_effective_profile_readback": "unavailable: codex sandbox 0.156.1 has no effective-profile display",
            "strict_config": self.strict_config_status(),
        }

    def strict_config_status(self) -> str:
        command = [self.cli, "--strict-config", "sandbox", "-C", str(self.work), "-P", "keepout",
                   "-c", "permissions.keepout=" + self.profile, "--", "/bin/echo", "EXPOSED"]
        result = subprocess.run(command, cwd=self.work, env=self.env, capture_output=True, text=True, timeout=12)
        if "not supported for `codex sandbox`" in result.stderr:
            return "rejected: --strict-config is not supported for codex sandbox"
        return self._clean(f"exit {result.returncode}; {result.stderr[:180]}")

    def __exit__(self, *_: object) -> None:
        for child in self.listeners:
            if child.poll() is None:
                child.terminate()  # exact Popen PID, never a process name or group
                try:
                    child.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    child.kill()  # same exact PID, only if our child did not exit
                    child.wait(timeout=3)
            if child.stdout:
                child.stdout.close()
            if child.stderr:
                child.stderr.close()
        if self.temp:
            self.temp.cleanup()

    def version(self) -> str:
        result = subprocess.run([self.cli, "--version"], cwd=self.work, env=self.env,
                                capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            raise RuntimeError("codex --version failed: " + self._clean(result.stderr))
        return result.stdout.strip()

    def _start_listener(self, kind: str) -> str:
        address = str(self.root / "local.sock") if kind == "unix" else "unused"
        child = subprocess.Popen([PYTHON, "-B", "-c", LISTENER, kind, address],
                                 cwd=self.work, env=self.env, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, text=True)
        self.listeners.append(child)
        assert child.stdout is not None
        ready, _, _ = select.select([child.stdout], [], [], 5)
        line = child.stdout.readline().strip() if ready else ""
        if not line or (kind == "unix" and line != "READY") or (kind == "tcp" and not line.isdigit()):
            return ""
        return line

    def _command(self, check: Check, sandboxed: bool) -> list[str]:
        if check.kind == "allowed_read":
            return ["/bin/sh", "-c", SHELL_READ, "sh", str(self.work / "allowed-canary"), self.marker]
        if check.kind == "allowed_write":
            return [PYTHON, "-B", "-c", WRITE, str(self.work / "allowed-write")]
        if check.kind == "allowed_command":
            return ["/bin/echo", "EXPOSED"]
        if check.kind in ("shell_read", "symlink_read"):
            target = self.work / "protected-link" if check.kind == "symlink_read" else self.targets[check.target]
            return ["/bin/sh", "-c", SHELL_READ, "sh", str(target), self.marker]
        if check.kind == "python_read":
            return [PYTHON, "-B", "-c", PYTHON_READ, str(self.targets[check.target]), self.marker]
        if check.kind in ("write_config", "write_outside"):
            folder = self.root / check.target
            path = folder / ("sandbox-write" if sandboxed else "control-write")
            return [PYTHON, "-B", "-c", WRITE, str(path)]
        if check.kind == "tcp":
            return [PYTHON, "-B", "-c", TCP, self.tcp_port or "0"]
        if check.kind == "unix":
            return [PYTHON, "-B", "-c", UNIX, str(self.unix_path)]
        if check.kind in ("env", "env_filtered"):
            return [PYTHON, "-B", "-c", ENV, self.token]
        if check.kind == "dns":
            return [PYTHON, "-B", "-c", DNS]
        if check.kind == "offhost":
            return [PYTHON, "-B", "-c", OFFHOST]
        raise ValueError(f"unknown check kind: {check.kind}")

    def run(self, check: Check, sandboxed: bool, profile_override: str | None = None) -> Observation:
        if check.kind == "tcp" and self.tcp_port is None:
            self.tcp_port = self._start_listener("tcp")
        if check.kind == "unix" and self.unix_path is None:
            if self._start_listener("unix"):
                self.unix_path = self.root / "local.sock"
        if (check.kind == "tcp" and not self.tcp_port) or (check.kind == "unix" and not self.unix_path):
            return Observation("ERROR", "owned listener failed to start")
        command = self._command(check, sandboxed)
        if sandboxed:
            command = [self.cli, "sandbox", "-C", str(self.work), "-P", "keepout",
                       "-c", "permissions.keepout=" + (profile_override or self.profile)]
            if check.kind == "env_filtered":
                command.extend(["-c", "shell_environment_policy.inherit=none"])
            command.extend(["--", *self._command(check, sandboxed)])
        try:
            result = subprocess.run(command, cwd=self.work, env=self.env, capture_output=True,
                                    text=True, timeout=12)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return Observation("ERROR", self._clean(f"probe could not complete: {type(exc).__name__}"))
        stdout = result.stdout.strip()
        stderr = result.stderr.strip()
        if result.returncode == 0 and stdout == "EXPOSED":
            state = "EXPOSED"
        elif result.returncode == 0 and stdout == "BLOCKED":
            state = "BLOCKED"
        elif result.returncode == 20 and ("Operation not permitted" in stderr or "Permission denied" in stderr):
            state = "BLOCKED"
        else:
            state = "ERROR"
        snippet = f"exit {result.returncode}; stdout={stdout[:100]!r}; stderr={stderr[:180]!r}"
        return Observation(state, self._clean(snippet))

    def rule_omission(self) -> dict[str, str]:
        """Show that dropping a deny rule produces an exposure, never a false PASS."""
        from .checks import evaluate
        first = self.policy.protected_paths[0]
        check = Check("omitted-rule", "Deliberately omit one protected-path deny", "shell_read", first)
        omitted = self._profile(omit=first)
        runner = self

        class OmittedRunner:
            def run(self, item: Check, sandboxed: bool) -> Observation:
                return runner.run(item, sandboxed, omitted if sandboxed else None)

        observed = evaluate(check, OmittedRunner())
        return {
            "verdict": "PASS" if observed["verdict"] == "FAIL" else "INVALID",
            "probe_verdict_without_rule": observed["verdict"],
            "rule": first,
            "evidence": observed["sandbox_evidence"],
            "omitted_profile_override": self._clean("permissions.keepout=" + omitted),
        }

    def _clean(self, value: str) -> str:
        return (value.replace(self.marker, "<redacted>")
                .replace(self.token, "<redacted>")
                .replace(str(self.root), "<temp>")
                .replace(str(Path.home()), "~"))
