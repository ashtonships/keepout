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

v0 sends direct shell and Python commands through `codex sandbox`. It does **not** run a model turn, agent tools, browser or connector tools, or real credentials. It does not verify an existing user's Codex configuration. It does not test Linux. The Claude Code harness below tests only the open-source sandbox-runtime CLI. DNS and off-host TCP are unmeasured with the bundled policy. A PASS says only that the listed action behaved as observed under this generated profile.

## Claude Code harness

Scope: **sandbox-runtime srt <version> (the open-source sandbox Claude Code builds on). Not Claude Code's bundled copy, not a model turn.** Claude Code 2.1.288 has no `claude sandbox` subcommand, and its bundled sandbox-runtime copy (version not exposed) and the layers Claude Code adds on top can only be reached through a model turn, so they are reported as UNMEASURED. macOS (Seatbelt) only; the Linux bubblewrap path is UNMEASURED.

The harness runs the same checks, controls, omitted-rule check and disclosure hold as the Codex harness. It writes srt settings files at the disposable root (never writable): `denyRead` for protected paths, `allowWrite` for writable paths, `allowedDomains: []`, and `allowLocalBinding`/`allowAllUnixSockets` set from the policy's `network`. The filtered-token variant adds `credentials.envVars` with `mode: "deny"` for the fake token. It always passes `--settings`, so srt never reads a real `~/.srt-settings.json`; HOME, TMPDIR and `CLAUDE_CODE_TMPDIR` point into the disposable root. If srt rejects a settings file, the probe is ERROR (never a denial PASS). With `network = true`, DNS and off-host TCP are UNMEASURED: srt has no full-network mode (`allowedDomains: ["*"]` is rejected) and direct-socket probes bypass its proxy. srt always allows writes to stdio, `/tmp/claude` and `/private/tmp/claude`, and to `~/.npm/_logs` and `~/.claude/debug` under the fake HOME unless a `denyRead` entry covers them.

Install srt without running package scripts (Node.js required; nothing is downloaded at run time):

```sh
npm install --ignore-scripts --no-audit --no-fund --prefix "$TMPDIR/keepout-srt" @anthropic-ai/sandbox-runtime@0.0.78
KEEPOUT_SRT="$TMPDIR/keepout-srt/node_modules/@anthropic-ai/sandbox-runtime/dist/cli.js" \
  python3 -m keepout run --harness claude --policy policy.toml --json results/local.json --md results/local.md
```

`KEEPOUT_SRT` may also name the `.bin/srt` shim; otherwise `srt` on `PATH` is used. Setting `KEEPOUT_SRT` also enables a live test in `python3 -m unittest`.

The [October 3 macOS result](results/2026-10-03-macos-claude-sandbox-runtime-0.0.78.md) records srt 0.0.78 with the bundled policy: controls passed, no denial failures, the inherited token EXPECTED-VISIBLE, DNS and off-host TCP UNMEASURED. It applies to srt 0.0.78 on that macOS build only, not to Claude Code's bundled copy.

Not reachable without a model turn (UNMEASURED):

- claude permissions.deny Read()/Edit() merged into sandbox
- Claude Code protected paths (.claude, .mcp.json, .git hooks/config, ~/.claude)
- excludedCommands / allowUnsandboxedCommands / dangerouslyDisableSandbox retry
- CLAUDE_CODE_SUBPROCESS_ENV_SCRUB
- failIfUnavailable
- Read/Edit/WebFetch tools, hooks, MCP (outside sandbox by design)
- Claude Code bundled sandbox-runtime version (not exposed)

## Disclosure

Each result has a `classification`: `documented_behavior` for expected behavior such as inherited environment visibility, `configuration_outcome` for a measured profile outcome, `pending_review` for any new denial failure, or `suspected_undocumented_bypass` when an unexplained bypass warrants vendor review. **A new denial failure is held by default:** it is classified `pending_review`, and the report writer replaces its identifier, description and evidence with **“held for private vendor report”** before writing JSON, Markdown or console output, the same as a suspected bypass. A person reviews it and either reclassifies it (documented behavior or configuration outcome) or reports it privately to the vendor. Future automated publishing must use this same publication boundary. No current result establishes a vendor vulnerability.

Licensed under the [MIT License](LICENSE).
