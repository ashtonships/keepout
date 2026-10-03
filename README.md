# Keepout v0

Keepout runs disposable commands against a generated Codex CLI permission profile and saves dated observations. **v0 tests a generated Codex permission profile derived from a Keepout test policy. v0.2 adds a linter for an existing Codex `config.toml` and a runner that tests one of its permission profiles against remapped disposable canaries.** A result applies to the tested CLI version, policy, machine, and routes. It is not a security certification.

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

## Results matrix and release watch

```sh
python3 -m keepout matrix results/ --html results/matrix.html --md results/matrix.md
python3 -m keepout watch --harness codex --policy policy.toml --results results/ [--dry-run] [--force]
```

`matrix` renders saved result files as one table: one column per harness, CLI version and OS (the newest run wins; older and superseded runs go to History). The HTML page is self-contained, with no scripts and no external files. Every check passes through the publication boundary again. **Held rule:** if a run has any held check (`pending_review` or `suspected_undocumented_bypass`, including a legacy FAIL with no classification), every denial cell in that run shows `held`, so the held check cannot be found from the cells. The row list still comes from public check ids, so when a held run is the only run with its policy, a missing denial row can hint at the held check; the per-run result files also list every other check by id. Review both before sharing a held run. **Leak guard:** if any value looks like an unredacted temporary path, home path or random canary, the command refuses to render and writes nothing (exit 2). It never redacts silently. Legacy runs without allowed-action and omitted-rule controls are labelled as such and are never shown as control-validated.

`watch` reruns the suite only when no result exists for this CLI version, OS and policy. It reads the version through the Codex binary in a throwaway HOME and never runs `codex update` or a shell. If the version changes during a run, it writes no result. If the CLI is missing, it logs UNMEASURED. Each check appends one line to `results/watch-log.jsonl`. `--dry-run` writes nothing. No scheduler is installed.

## Lint an existing config

```sh
python3 -m keepout lint CONFIG [--profile NAME] [--json FILE] [--codex-check]
python3 -m keepout lint tests/fixtures/lint/KO020.toml --profile p
```

Keepout reads exactly the one file it is given, with `tomllib`. It refuses a file under the real `~/.codex`, `~/.claude`, `~/.ssh` or `~/.config` unless you pass `--i-own-this-file`, and even then it never reads that file's siblings. Each finding prints as `ID SEVERITY file:line message`, followed by `why:` and `fix:`. `--json` writes a list of `{id, severity, title, why, fix, line, profile, path, measured, evidence_fixture}`. The exit code is 2 for any `error` (Codex will refuse to start), 1 for any `high` (a rule silently does not protect), and 0 otherwise.

`--codex-check` is the only lint mode that runs Codex. It writes a sanitized copy to a fake `CODEX_HOME` in a temporary folder. The copy holds only top-level scalars and arrays, `[permissions.*]` and `[sandbox_workspace_write]`; it never includes `mcp_servers`, hooks, `notify`, model providers, profiles or shell environment policy. Keepout then runs `codex exec --ephemeral` twice, once with `--strict-config` and once without, against a dead provider at `127.0.0.1:9`. This is only a session start: there is no auth and no model turn is possible. Measured on 0.156.1, a plain `codex exec` without that override contacts api.openai.com, so Keepout never runs it. Codex's own warnings are attached to the matching finding as `codex_said`. Fixtures write `{R}` for a disposable root, and Keepout reads `{R}` as `/keepout-fixture-root`.

| ID | Severity | Rule | Evidence |
| --- | --- | --- | --- |
| KO001 | error | Config does not parse (incl. duplicate key) | measured |
| KO002 | high | `sandbox_permissions` is ignored (silent under `codex sandbox`) | measured |
| KO003 | info | Top-level key not in Keepout's 0.156.1 list | doc-only |
| KO010 | high | Unknown key inside `[permissions.X]` (ignored even with `--strict-config`) | measured |
| KO011 | high | `network.mode` is ignored; only `enabled` works | measured |
| KO012 | high | Unknown network key | measured |
| KO013 | high | Unknown `:token` (silently ignored by `codex sandbox`) | measured |
| KO014 | error | Access value outside read/write/deny (case-sensitive) | measured |
| KO015 | info | Undocumented value `none` (denies reads) | measured |
| KO016 | error | Relative filesystem path | measured |
| KO020 | high | `:minimal` without a read base leaves /private/tmp readable | measured |
| KO021 | high | `:root` deny with no `:minimal`: commands exit 134 | measured |
| KO022 | medium | Read/write rule inside a deny re-opens that subtree | measured |
| KO023 | info | Same canonical path both denied and allowed (deny wins) | measured |
| KO024 | high | Child profile replaces a parent deny with read/write | measured |
| KO030 | info | Non-canonical path (alias, `//`, trailing `/`, `..`) | measured |
| KO031 | info | `~/` path follows the Codex process's $HOME | measured |
| KO040 | medium | `sandbox_mode`/`sandbox_workspace_write` next to `default_permissions` | measured |
| KO041 | error | `[permissions]` without `default_permissions` (exec refuses) | measured |
| KO042 | error | `default_permissions` or `--profile` names an undefined profile | measured |
| KO043 | error | Unsupported built-in, undefined parent or cycle in `extends` | measured |
| KO050 | info | Extends `:workspace` (also writes /tmp and $TMPDIR) | measured |
| KO051 | info | Network enabled for a `*` or `**.` domain | doc-only |
| KO090 | medium | A message Codex printed during `--codex-check` | measured per run |

"Measured" means codex-cli 0.156.1 on macOS, 2026-10-03, with a fixture in `tests/fixtures/lint/<ID>.toml`.

## Run an existing profile

```sh
python3 -m keepout run --harness codex --config CONFIG --profile NAME [--json F --md F]
python3 -m keepout run --harness codex --config tests/fixtures/lint/KO020.toml --profile p \
  --json results/imported/2026-10-03-imported-KO020.json --md results/imported/2026-10-03-imported-KO020.md
KEEPOUT_LIVE=1 python3 -m unittest tests.test_imported -v
```

`--config` and `--policy` cannot be used together. Keepout creates a disposable root under the system temporary folder. It refuses to run if that root is under /private/tmp, because `:minimal` makes /private/tmp readable. Every configured path is remapped by string work alone, and Keepout never stats, reads or writes the real path: an absolute `P` becomes `<root>/abs/P`, `~/x` stays `~/x` under a fake HOME, `:tmpdir` maps to the fake TMPDIR, and `:workspace_roots` maps to the `-C` workspace. Paths containing `..` are refused. The generated `config.toml` carries only the profile's `[permissions.*]` extends chain, and the report lists every dropped top-level key. The one exception is a `"/private/tmp" = "deny"` entry, which is also kept unremapped. A deny only restricts, and keeping it shows whether it covers `:minimal`.

Each deny entry is probed in two shapes, as a folder and as a file, each in its own fresh subroot. Each read entry must be readable, and writing to it must be blocked. Each write entry must accept a new file. Globs are probed with a synthesized matching path, both planted beforehand and created inside the sandbox. Loopback TCP and Unix sockets are expected to be allowed only when `network.enabled = true`. Machine-wide tokens (`:root`, `:minimal`, `:slash_tmp`), overridden parent entries, `domains` and `unix_sockets` are UNMEASURED, with the reason recorded. When a profile uses `:minimal`, Keepout plants a canary in a fresh folder it creates under /private/tmp and removes that folder afterwards.

Controls work as in the policy runner. Every allowed action and `/bin/echo` must pass inside the sandbox. Every denial needs an exposed unsandboxed control. Each deny rule's first probe is rerun with that rule removed and recorded as `load_bearing`. The run-wide omitted-rule check on Keepout's bundled profile must pass. If any control fails, every denial is INVALID.

A FAIL is `pending_review` and is withheld from JSON, Markdown and console output, unless its `(row kind, lint id)` is in `KNOWN_OUTCOMES` in `keepout/imported.py`. That table covers `minimal-tmp-exposure`/KO020, `carve-out`/KO022, `extends-relax`/KO024, `ignored-network-key`/KO011 and `ignored-token`/KO013, each with its 2026-10-03 measurement receipt. **A person must review any change to `KNOWN_OUTCOMES`**, because the table decides what is published. Public reports shorten original config paths to their last two components.

Findings and results apply to codex-cli 0.156.1 on this macOS machine; none is a vendor vulnerability claim. `:minimal`'s /private/tmp read is documented-by-design platform defaults, reported because it defeats a common :root-deny intent.

The [config result](results/imported/2026-10-03-macos-codex-0.156.1-config.md) runs `tests/fixtures/config/2026-09-26-failure-modes.toml`, a worker profile shaped like the Engine's 26 Sep 2026 worker-isolation starting point. With controls passing, it shows four configuration outcomes:
- the child profile removes the parent's deny (KO024);
- a write inside a deny re-opens it (KO022);
- `:home` is ignored (KO013);
- `network.mode = "full"` leaves loopback blocked (KO011).

Per-rule receipts are in `results/imported/2026-10-03-imported-*.md`.

## Disclosure

Each result has a `classification`: `documented_behavior` for expected behavior such as inherited environment visibility, `configuration_outcome` for a measured profile outcome, `pending_review` for any new denial failure, or `suspected_undocumented_bypass` when an unexplained bypass warrants vendor review. **A new denial failure is held by default:** it is classified `pending_review`, and the report writer replaces its identifier, description and evidence with **“held for private vendor report”** before writing JSON, Markdown or console output, the same as a suspected bypass. A person reviews it and either reclassifies it (documented behavior or configuration outcome) or reports it privately to the vendor. Future automated publishing must use this same publication boundary. No current result establishes a vendor vulnerability.

Licensed under the [MIT License](LICENSE).
