"""Claude Code's open-source sandbox (sandbox-runtime `srt`) probes. Every path and credential value is disposable.

This measures the npm sandbox-runtime CLI that Claude Code builds on, not Claude Code's bundled copy and not a
model turn. Claude Code layers that only a model turn reaches are listed in UNREACHABLE and reported as UNMEASURED.
"""

from __future__ import annotations

import dataclasses
import json
import os
from pathlib import Path
import shutil
import subprocess

from .checks import Check, Observation
from .policy import Policy
from .probes import DisposableRoot


INSTALL_HINT = ('srt not found; install with: npm install --ignore-scripts --prefix "$TMPDIR/keepout-srt" '
                "@anthropic-ai/sandbox-runtime@0.0.78 and set "
                "KEEPOUT_SRT=$TMPDIR/keepout-srt/node_modules/@anthropic-ai/sandbox-runtime/dist/cli.js")
UNREACHABLE = [
    "claude permissions.deny Read()/Edit() merged into sandbox",
    "Claude Code protected paths (.claude, .mcp.json, .git hooks/config, ~/.claude)",
    "excludedCommands / allowUnsandboxedCommands / dangerouslyDisableSandbox retry",
    "CLAUDE_CODE_SUBPROCESS_ENV_SCRUB",
    "failIfUnavailable",
    "Read/Edit/WebFetch tools, hooks, MCP (outside sandbox by design)",
    "Claude Code bundled sandbox-runtime version (not exposed)",
]
NETWORK_UNSUPPORTED = ("srt has no full-network mode (allowedDomains '*' rejected); direct-socket probes bypass "
                       "its proxy, so they do not model allowed-domain access")


def find_srt() -> str:
    override = os.environ.get("KEEPOUT_SRT")
    if override:
        path = Path(override).resolve()
        if path.is_file():
            return str(path)
        raise FileNotFoundError(f"KEEPOUT_SRT does not name a file. {INSTALL_HINT}")
    found = shutil.which("srt")
    if found:
        return str(Path(found).resolve())
    raise FileNotFoundError(INSTALL_HINT)


def find_node() -> str:
    found = shutil.which("node")
    if not found:
        raise FileNotFoundError("node was not found on PATH; srt needs Node.js")
    return str(Path(found).resolve())


class ClaudeRunner(DisposableRoot):
    HARNESS = ("sandbox-runtime {version} (the open-source sandbox Claude Code builds on). "
               "Not Claude Code's bundled copy, not a model turn.")
    REJECTED = "srt rejected settings"
    env_filter_miss = "srt credentials.envVars deny not applied; variable remained visible"

    def __init__(self, policy: Policy, srt: str | None = None, node: str | None = None):
        super().__init__(policy)
        self.srt = srt or find_srt()
        self.node = node or find_node()  # resolved before the filtered environment exists

    def __enter__(self) -> "ClaudeRunner":
        self._make_root()
        self.env = {
            "PATH": "/usr/bin:/bin:/opt/homebrew/bin",
            "HOME": str(self.home),
            "TMPDIR": str(self.root / "tmp"),
            "CLAUDE_CODE_TMPDIR": str(self.root / "tmp"),  # keeps srt off the shared /tmp/claude
            "KEEPOUT_FAKE_TOKEN": self.token,
            "LANG": "en_US.UTF-8",
        }
        # Settings files live at the root, which is never in allowWrite.
        self.settings = self._settings()
        self.settings_file = self._write_settings("srt-settings.json", self.settings)
        self.env_settings = self._settings(filter_env=True)
        self.env_settings_file = self._write_settings("srt-settings-env.json", self.env_settings)
        self.omit_settings = self._settings(omit=self.policy.protected_paths[0])
        self.omit_settings_file = self._write_settings("srt-settings-omit.json", self.omit_settings)
        return self

    def __exit__(self, *_: object) -> None:
        self._close()

    def _settings(self, omit: str | None = None, filter_env: bool = False) -> dict[str, object]:
        settings: dict[str, object] = {
            "filesystem": {
                "denyRead": [str(self.root / path) for path in self.policy.protected_paths if path != omit],
                "allowRead": [],
                "allowWrite": [str(self.root / path) for path in self.policy.writable_paths],
                "denyWrite": [],
            },
            "network": {
                "allowedDomains": [],
                "deniedDomains": [],
                "allowLocalBinding": self.policy.network,
                "allowAllUnixSockets": self.policy.network,
            },
        }
        if filter_env:
            settings["credentials"] = {"envVars": [{"name": "KEEPOUT_FAKE_TOKEN", "mode": "deny"}]}
        return settings

    def _write_settings(self, name: str, settings: dict[str, object]) -> Path:
        path = self.root / name
        path.write_text(json.dumps(settings, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        return path

    def adjust(self, checks: list[Check]) -> list[Check]:
        if not self.policy.network:
            return checks
        return [dataclasses.replace(check, unsupported_reason=NETWORK_UNSUPPORTED)
                if check.kind in ("dns", "offhost") else check for check in checks]

    def _rejected(self, stderr: str) -> bool:
        return stderr.startswith("Error:") or "Refusing to run" in stderr

    def run(self, check: Check, sandboxed: bool, settings_path: Path | str | None = None) -> Observation:
        error = self._listener_error(check)
        if error:
            return error
        command = self._command(check, sandboxed)
        if sandboxed:
            settings = settings_path or (self.env_settings_file if check.kind == "env_filtered"
                                         else self.settings_file)
            command = [self.node, self.srt, "--settings", str(settings), "--", *command]
        return self._execute(command, sandboxed)

    def rule_omission(self) -> dict[str, str]:
        """Show that dropping a deny rule produces an exposure, never a false PASS."""
        from .checks import evaluate
        first = self.policy.protected_paths[0]
        check = Check("omitted-rule", "Deliberately omit one protected-path deny", "shell_read", first)
        omitted = self.omit_settings_file
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
            "omitted_profile_override": self._clean(json.dumps(self.omit_settings, sort_keys=True)),
        }

    def version(self) -> str:
        result = subprocess.run([self.node, self.srt, "--version"], cwd=self.work, env=self.env,
                                capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            raise RuntimeError("srt --version failed: " + self._clean(result.stderr))
        return "srt " + result.stdout.strip()

    def node_version(self) -> str:
        result = subprocess.run([self.node, "--version"], cwd=self.work, env=self.env,
                                capture_output=True, text=True, timeout=10)
        return result.stdout.strip() if result.returncode == 0 else "unknown"

    def strict_config_status(self) -> str:
        invalid = self._write_settings("srt-settings-invalid.json", {"network": {"allowedDomains": ["*"]}})
        command = [self.node, self.srt, "--settings", str(invalid), "--", "/bin/echo", "EXPOSED"]
        try:
            result = subprocess.run(command, cwd=self.work, env=self.env, capture_output=True, text=True, timeout=12)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return f"unmeasured: {type(exc).__name__}"
        if (("Refusing to run" in result.stderr or "does not hold a valid config" in result.stderr)
                and "EXPOSED" not in result.stdout):
            return f"rejects invalid settings (exit {result.returncode})"
        return self._clean(f"exit {result.returncode}; stdout={result.stdout[:60]!r}; stderr={result.stderr[:180]!r}")

    def receipt(self) -> dict[str, object]:
        network = self.policy.network
        return {
            "config_overrides": [self._clean(json.dumps(self.settings, sort_keys=True)),
                                 self._clean(json.dumps(self.env_settings, sort_keys=True))],
            "environment_override_scope": "filtered-token only (credentials.envVars deny)",
            "generated_profile_network_mode": (f"proxy-only, allowedDomains=[], localBinding={network}, "
                                               f"allUnixSockets={network}"),
            "codex_effective_profile_readback": (f"unavailable: {self.version()} has no effective-config readback; "
                                                 "Claude Code's bundled copy not tested"),
            "strict_config": self.strict_config_status(),
            "srt_version": self.version(),
            "node_version": self.node_version(),
            "sandbox_exec": Path("/usr/bin/sandbox-exec").exists(),
            "default_writable_note": ("srt always allows writes to stdio, /tmp/claude, /private/tmp/claude, and "
                                      "~/.npm/_logs, ~/.claude/debug under the fake HOME"),
            "platform_scope": "macOS Seatbelt only; the Linux bubblewrap path is UNMEASURED",
            "unreachable_without_model_turn": list(UNREACHABLE),
        }

    def _srt_dir(self) -> str:
        path = Path(self.srt)
        for parent in path.parents:
            if parent.name == "node_modules":
                return str(parent.parent)
        return str(path.parent)

    def _clean(self, value: str) -> str:
        return super()._clean(value.replace(self._srt_dir(), "<srt>"))
