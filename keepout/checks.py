"""Verdicts and the control rule, independent of any subprocess."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class Observation:
    state: str  # EXPOSED, BLOCKED, or ERROR
    evidence: str


@dataclass(frozen=True)
class Check:
    id: str
    description: str
    kind: str
    target: str = ""
    unsupported_reason: str = ""


class Runner(Protocol):
    def run(self, check: Check, sandboxed: bool) -> Observation: ...


def evaluate(check: Check, runner: Runner) -> dict[str, str]:
    """A denial passes only after an unsandboxed control proves the probe works."""
    if check.unsupported_reason:
        return _result(check, "UNMEASURED", "not run", check.unsupported_reason)
    control = runner.run(check, False)
    if control.state != "EXPOSED":
        return _result(check, "INVALID", control.evidence, "control did not observe exposure")
    sandbox = runner.run(check, True)
    if sandbox.state == "ERROR":
        verdict = "UNMEASURED"
    elif sandbox.state == "BLOCKED":
        verdict = "PASS"
    else:
        verdict = "FAIL"
    return _result(check, verdict, control.evidence, sandbox.evidence)


def _result(check: Check, verdict: str, control: str, sandbox: str) -> dict[str, str]:
    return {
        "id": check.id,
        "description": check.description,
        "verdict": verdict,
        "control_evidence": control,
        "sandbox_evidence": sandbox,
    }


def make_checks(protected: tuple[str, ...], network: bool, inherit_fake_token: bool) -> list[Check]:
    checks = []
    for path in protected:
        checks.extend((
            Check(f"read-shell:{path}", f"Shell read of {path}", "shell_read", path),
            Check(f"read-python:{path}", f"Python read of {path}", "python_read", path),
        ))
    if "home/.ssh" in protected:
        checks.append(Check("read-symlink", "Read protected canary through writable symlink", "symlink_read", "home/.ssh"))
    else:
        checks.append(Check("read-symlink", "Read protected canary through writable symlink", "symlink_read",
                            unsupported_reason="policy has no home/.ssh protected path"))
    if "home/.config/codex" in protected:
        checks.append(Check("write-config", "Write agent's fake config folder", "write_config", "home/.config/codex"))
    else:
        checks.append(Check("write-config", "Write agent's fake config folder", "write_config",
                            unsupported_reason="policy has no home/.config/codex protected path"))
    checks.append(Check("write-outside", "Write outside declared writable paths", "write_outside", "outside"))
    allowed_network = "policy allows network; no denial is expected" if network else ""
    checks.append(Check("tcp-loopback", "Connect to owned 127.0.0.1 listener", "tcp",
                        unsupported_reason=allowed_network))
    checks.append(Check("unix-socket", "Connect to owned Unix socket", "unix",
                        unsupported_reason=allowed_network))
    checks.append(Check("inherited-token", "Observe fake inherited environment token", "env",
                        unsupported_reason="policy allows token inheritance; no denial is expected" if inherit_fake_token else ""))
    checks.append(Check("tcp-off-host", "Outbound off-host TCP connect", "offhost",
                        unsupported_reason="off-host network access is disallowed for this run"))
    return checks
