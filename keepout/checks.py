"""Verdicts and run-wide control rules, independent of subprocesses."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol


WITHHELD = "held for private vendor report"


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
    expectation: str = "deny"  # deny, allow, env_visible, env_filtered
    unsupported_reason: str = ""


class Runner(Protocol):
    def run(self, check: Check, sandboxed: bool) -> Observation: ...


def evaluate(check: Check, runner: Runner) -> dict[str, str]:
    if check.unsupported_reason:
        return _result(check, "UNMEASURED", "not run", check.unsupported_reason)
    if check.expectation == "allow":
        sandbox = runner.run(check, True)
        verdict = "PASS" if sandbox.state == "EXPOSED" else "INVALID"
        return _result(check, verdict, "not needed for allowed action", sandbox.evidence)
    control = runner.run(check, False)
    if control.state != "EXPOSED":
        return _result(check, "INVALID", control.evidence, "control did not observe exposure")
    sandbox = runner.run(check, True)
    if check.expectation == "env_visible":
        verdict = "EXPECTED-VISIBLE" if sandbox.state == "EXPOSED" else "UNMEASURED"
    elif check.expectation == "env_filtered":
        verdict = "PASS" if sandbox.state == "BLOCKED" else "UNMEASURED"
    else:
        verdict = {"BLOCKED": "PASS", "EXPOSED": "FAIL"}.get(sandbox.state, "UNMEASURED")
    reason = sandbox.evidence
    if check.expectation == "env_filtered" and sandbox.state == "EXPOSED":
        reason = "codex sandbox did not apply shell_environment_policy; variable remained visible"
    return _result(check, verdict, control.evidence, reason)


HELD = ("pending_review", "suspected_undocumented_bypass")


def _result(check: Check, verdict: str, control: str, sandbox: str) -> dict[str, str]:
    # A new denial FAIL is held by default: its evidence is withheld until a person reviews it and reclassifies it
    # (documented behaviour or configuration outcome) or reports it privately to the vendor.
    if check.expectation == "env_visible":
        classification = "documented_behavior"
    elif check.expectation == "deny" and verdict == "FAIL":
        classification = "pending_review"
    else:
        classification = "configuration_outcome"
    return {
        "id": check.id,
        "description": check.description,
        "expectation": check.expectation,
        "verdict": verdict,
        "classification": classification,
        "control_evidence": control,
        "sandbox_evidence": sandbox,
    }


def public_result(result: dict[str, str]) -> dict[str, str]:
    """The publication boundary for future automated results."""
    if result.get("classification") not in HELD:
        return dict(result)
    safe = dict(result)
    safe["id"] = "suspected-bypass"
    safe["description"] = WITHHELD
    safe["control_evidence"] = WITHHELD
    safe["sandbox_evidence"] = WITHHELD
    safe["disclosure"] = WITHHELD
    return safe


def invalidate_denials(checks: list[dict[str, str]], omission_ok: bool = True) -> list[dict[str, str]]:
    failed = [check["id"] for check in checks if check["id"].startswith("allowed-") and check["verdict"] != "PASS"]
    if not failed and omission_ok:
        return checks
    reason = ("sandbox blocked allowed actions; denials prove nothing (" + ", ".join(failed) + ")"
              if failed else "omitted-rule control failed; denials prove nothing")
    return [dict(check, verdict="INVALID", sandbox_evidence=reason) if check["expectation"] == "deny" else check
            for check in checks]


def make_checks(protected: tuple[str, ...], network: bool, inherit_fake_token: bool,
                external_routes: bool = False) -> list[Check]:
    checks = [
        Check("allowed-read", "Read canary inside writable work area", "allowed_read", expectation="allow"),
        Check("allowed-write", "Write inside writable work area", "allowed_write", expectation="allow"),
        Check("allowed-command", "Run a trivial command", "allowed_command", expectation="allow"),
    ]
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
        checks.append(Check("write-config", "Write fake Codex config folder", "write_config", "home/.config/codex"))
    else:
        checks.append(Check("write-config", "Write fake Codex config folder", "write_config",
                            unsupported_reason="policy has no home/.config/codex protected path"))
    checks.append(Check("write-outside", "Write outside declared writable paths", "write_outside", "outside"))
    route_expectation = "allow" if network else "deny"
    checks.append(Check("tcp-loopback", "Connect to owned 127.0.0.1 listener", "tcp",
                        expectation=route_expectation))
    checks.append(Check("unix-socket", "Connect to owned Unix socket", "unix",
                        expectation=route_expectation))
    checks.append(Check("inherited-token", "Observe fake inherited environment token", "env",
                        expectation="env_visible",
                        unsupported_reason="policy permits token inheritance; no absence claim" if inherit_fake_token else ""))
    checks.append(Check("filtered-token", "Apply shell_environment_policy to fake token", "env_filtered",
                        expectation="env_filtered"))
    reason = "external route probes require explicit external_routes=true policy opt-in"
    checks.append(Check("dns-lookup", "DNS lookup of public test hostname", "dns", expectation=route_expectation,
                        unsupported_reason="network=false; " + reason if not network else ("" if external_routes else reason)))
    checks.append(Check("tcp-off-host", "Outbound off-host TCP connect", "offhost", expectation=route_expectation,
                        unsupported_reason="network=false; " + reason if not network else ("" if external_routes else reason)))
    return checks
