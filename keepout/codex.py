"""Codex CLI probes. Every path and credential value here is disposable."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import tomllib

from .checks import Check, Observation
from .policy import Policy
from .probes import (DNS, ENV, LISTENER, OFFHOST, PYTHON, PYTHON_READ, SHELL_READ, TCP, UNIX, WRITE,  # noqa: F401
                     DisposableRoot)


def find_codex() -> str:
    cli = shutil.which("codex") or "/opt/homebrew/bin/codex"
    if not Path(cli).is_file():
        raise FileNotFoundError("codex CLI was not found on PATH or at /opt/homebrew/bin/codex")
    return cli


def cli_version(cli: str | None = None) -> str:
    """`codex --version` in a throwaway HOME. Never a shell, never `codex update`."""
    binary = cli or find_codex()
    with tempfile.TemporaryDirectory(prefix="keepout-ver-", dir="/private/tmp") as name:
        root = Path(name).resolve()
        home = root / "home"
        codex_home = home / ".config" / "codex"
        for folder in (home, codex_home, root / "tmp"):
            folder.mkdir(parents=True, exist_ok=True)
        env = {"PATH": "/usr/bin:/bin:/opt/homebrew/bin", "HOME": str(home), "CODEX_HOME": str(codex_home),
               "TMPDIR": str(root / "tmp"), "LANG": "en_US.UTF-8"}
        try:
            result = subprocess.run([binary, "--version"], cwd=root, env=env, capture_output=True, text=True,
                                    timeout=10)
        except FileNotFoundError:
            raise
        except (subprocess.TimeoutExpired, OSError) as exc:
            raise RuntimeError(f"codex --version could not run ({type(exc).__name__})") from None
        if result.returncode != 0:
            raise RuntimeError(f"codex --version failed with exit {result.returncode}")
        return result.stdout.strip()


class CodexRunner(DisposableRoot):
    HARNESS = "codex sandbox named permission profile"

    def __init__(self, policy: Policy, cli: str | None = None):
        super().__init__(policy)
        self.cli = cli or find_codex()

    def __enter__(self) -> "CodexRunner":
        self._make_root(extra_dirs=("home/.config/codex",))
        self.codex_home = self.home / ".config" / "codex"
        self.env = {
            "PATH": "/usr/bin:/bin:/opt/homebrew/bin",
            "HOME": str(self.home),
            "CODEX_HOME": str(self.codex_home),
            "TMPDIR": str(self.root / "tmp"),
            "KEEPOUT_FAKE_TOKEN": self.token,
            "LANG": "en_US.UTF-8",
        }
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
        self._close()

    def version(self) -> str:
        result = subprocess.run([self.cli, "--version"], cwd=self.work, env=self.env,
                                capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            raise RuntimeError("codex --version failed: " + self._clean(result.stderr))
        return result.stdout.strip()

    def run(self, check: Check, sandboxed: bool, profile_override: str | None = None) -> Observation:
        error = self._listener_error(check)
        if error:
            return error
        command = self._command(check, sandboxed)
        if sandboxed:
            command = [self.cli, "sandbox", "-C", str(self.work), "-P", "keepout",
                       "-c", "permissions.keepout=" + (profile_override or self.profile)]
            if check.kind == "env_filtered":
                command.extend(["-c", "shell_environment_policy.inherit=none"])
            command.extend(["--", *self._command(check, sandboxed)])
        return self._execute(command, sandboxed)

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
