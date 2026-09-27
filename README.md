# Keepout v0

Keepout runs disposable commands against a generated Codex CLI permission profile and saves dated observations. **v0 tests a generated Codex permission profile derived from a Keepout test policy; importing and checking an existing Codex configuration is planned.** A result applies to the tested CLI version, policy, machine, and routes. It is not a security certification.

## Run

Requires macOS, Python 3.11 or newer, and a local Codex CLI on `PATH` or at `/opt/homebrew/bin/codex`. The suite uses the Python standard library and does not log in to Codex.

```sh
python3 -m unittest
python3 -m keepout list-checks
python3 -m keepout run --harness codex --policy policy.toml \
  --json results/local.json --md results/local.md
```

The [bundled policy](policy.toml) names directories relative to a disposable root. `work` is writable; protected and writable directories cannot overlap. Keepout rejects absolute paths and `..`. It creates fake HOME and CODEX_HOME directories, random file canaries, and a fake `KEEPOUT_FAKE_TOKEN`. The subprocess gets a small environment allowlist. Keepout does not read real keys or configuration. Temporary paths and random values are redacted in saved results.

The runner constructs a named profile extending `:read-only`, with `deny` entries for protected directories and `write` entries for writable directories. The policy's `network` value sets the generated profile's network mode: `false` becomes `limited`, `true` becomes `full`. Each result saves the exact generated `-c` overrides with temporary paths redacted and parses the generated profile back to record its network mode. Codex CLI 0.156.1 provides no effective-profile readback through `codex sandbox`; the recorded mode is the generated input, with behavior checked by probes. That subcommand also rejects `--strict-config`, so Keepout records the rejection. A separate fail-closed check omits one deny rule deliberately and requires its read probe to report exposure. If it cannot demonstrate that missing rule, denial results are invalidated.

Before denial checks, three actions must succeed **inside** the sandbox: reading from `work`, writing to `work`, and running `/bin/echo`. For each measured denial, the same action first runs unsandboxed and must demonstrate that the probe can reach its canary or listener. If any sandboxed allowed action fails, **every denial in that run is INVALID: “sandbox blocked allowed actions; denials prove nothing.”**

## Verdicts

| Verdict | Meaning |
| --- | --- |
| PASS | An allowed action succeeded, or a denial was observed after its unsandboxed control showed exposure. The filtered environment variant also uses PASS when its fake token is absent. |
| FAIL | A measured denial allowed the action after its control showed exposure. Only denial FAILs count as enforcement failures. |
| EXPECTED-VISIBLE | The inherited fake token remained visible without an environment filter: the declared absence expectation was not met, as expected for this configuration. This is never an enforcement failure. |
| INVALID | A required control failed, or the omitted-rule check could not show that a missing rule is detected. Denials then prove nothing. |
| UNMEASURED | A route was not run, is unsupported, or produced inconclusive evidence. The result records why. |

File reads use shell and Python variants. A symlink read starts in the writable directory. Write checks target a fake Codex configuration directory and another directory outside the writable list. Local TCP and Unix socket checks use separate verdicts and connect only to listeners Keepout starts; it terminates only those exact child processes. DNS lookup and off-host TCP have separate result rows, but are **UNMEASURED by default**. The policy must explicitly set both `network = true` and `external_routes = true` to opt into those external probes. The bundled policy does not opt in.

The inherited-token check is an environment observation, not a sandbox file or network enforcement check. Codex's file and network rules do not promise to strip inherited variables. A second variant passes `-c shell_environment_policy.inherit=none` to `codex sandbox` and checks whether the fake token disappears. If that policy is not applied or the observation is inconclusive, the variant is UNMEASURED, never FAIL.

## Current result and limits

The [September 27 round 2 macOS result](results/2026-09-27b-macos-codex-0.156.1.md) records Codex CLI 0.156.1 with the bundled policy. Its verdict counts and redacted profile receipt are in the result. The [earlier run](results/2026-09-27-macos-codex-0.156.1.md) remains for history; its inherited-token `FAIL` label is superseded because token inheritance is expected without an environment filter.

v0 sends direct shell and Python commands through `codex sandbox`. It does **not** run a model turn, agent tools, browser or connector tools, or real credentials. It does not verify an existing user's Codex configuration. It does not test Claude Code or Linux. DNS and off-host TCP are unmeasured with the bundled policy. A PASS says only that the listed action behaved as observed under this generated profile.

## Disclosure

Each result has a `classification`: `documented_behavior` for expected behavior such as inherited environment visibility, `configuration_outcome` for a measured profile outcome, `pending_review` for any new denial failure, or `suspected_undocumented_bypass` when an unexplained bypass warrants vendor review. **A new denial failure is held by default:** it is classified `pending_review`, and the report writer replaces its identifier, description and evidence with **“held for private vendor report”** before writing JSON, Markdown or console output, the same as a suspected bypass. A person reviews it and either reclassifies it (documented behavior or configuration outcome) or reports it privately to the vendor. Future automated publishing must use this same publication boundary. No current result establishes a vendor vulnerability.

Licensed under the [MIT License](LICENSE).
