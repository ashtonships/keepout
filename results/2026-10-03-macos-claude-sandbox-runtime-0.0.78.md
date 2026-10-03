# Keepout result

- Harness: `sandbox-runtime srt 0.0.78 (the open-source sandbox Claude Code builds on). Not Claude Code's bundled copy, not a model turn.`
- CLI: `srt 0.0.78`
- OS: `macOS-27.0.1-arm64-arm-64bit-Mach-O`
- Run time (UTC): `2026-10-03T16:52:54+00:00`
- Summary: controls passed; PASS 17, FAIL 0, INVALID 0, UNMEASURED 2, EXPECTED-VISIBLE 1; enforcement failures 0
- Generated network mode: `proxy-only, allowedDomains=[], localBinding=False, allUnixSockets=False`
- Effective profile readback: unavailable: srt 0.0.78 has no effective-config readback; Claude Code's bundled copy not tested
- Strict config: rejects invalid settings (allowedDomains '*' in otherwise valid settings; exit 1)
- Omitted-rule fail-closed check: PASS (probe without rule: FAIL)
- Omitted-rule configuration: `{"filesystem": {"allowRead": [], "allowWrite": ["<temp>/work"], "denyRead": ["<temp>/home/.config/codex", "<temp>/home/.config/secrets", "<temp>/protected"], "denyWrite": []}, "network": {"allowAllUnixSockets": false, "allowLocalBinding": false, "allowedDomains": [], "deniedDomains": []}}`
- Node: v22.23.1
- Platform scope: macOS Seatbelt only; the Linux bubblewrap path is UNMEASURED
- Default writable paths: srt always allows writes to stdio, /tmp/claude and /private/tmp/claude, and to ~/.npm/_logs and ~/.claude/debug under the fake HOME unless a denyRead entry covers them

Allowed-action controls run inside the sandbox. A denial PASS also requires an exposed unsandboxed control. If any allowed action fails, all denial verdicts are INVALID.

## Generated configuration (temporary paths redacted)

- `{"filesystem": {"allowRead": [], "allowWrite": ["<temp>/work"], "denyRead": ["<temp>/home/.ssh", "<temp>/home/.config/codex", "<temp>/home/.config/secrets", "<temp>/protected"], "denyWrite": []}, "network": {"allowAllUnixSockets": false, "allowLocalBinding": false, "allowedDomains": [], "deniedDomains": []}}`
- `{"credentials": {"envVars": [{"mode": "deny", "name": "KEEPOUT_FAKE_TOKEN"}]}, "filesystem": {"allowRead": [], "allowWrite": ["<temp>/work"], "denyRead": ["<temp>/home/.ssh", "<temp>/home/.config/codex", "<temp>/home/.config/secrets", "<temp>/protected"], "denyWrite": []}, "network": {"allowAllUnixSockets": false, "allowLocalBinding": false, "allowedDomains": [], "deniedDomains": []}}`
- Environment override scope: filtered-token only (credentials.envVars deny)

| Check | Verdict | Classification | Control evidence | Sandbox evidence |
| --- | --- | --- | --- | --- |
| allowed-read | PASS | configuration_outcome | not needed for allowed action | exit 0; stdout='EXPOSED'; stderr='' |
| allowed-write | PASS | configuration_outcome | not needed for allowed action | exit 0; stdout='EXPOSED'; stderr='' |
| allowed-command | PASS | configuration_outcome | not needed for allowed action | exit 0; stdout='EXPOSED'; stderr='' |
| read-shell:home/.ssh | PASS | configuration_outcome | exit 0; stdout='EXPOSED'; stderr='' | exit 20; stdout=''; stderr='cat: <temp>/home/.ssh/id_test: Operation not permitted' |
| read-python:home/.ssh | PASS | configuration_outcome | exit 0; stdout='EXPOSED'; stderr='' | exit 0; stdout='BLOCKED'; stderr='' |
| read-shell:home/.config/codex | PASS | configuration_outcome | exit 0; stdout='EXPOSED'; stderr='' | exit 20; stdout=''; stderr='cat: <temp>/home/.config/codex/settings.toml: Operation not permitted' |
| read-python:home/.config/codex | PASS | configuration_outcome | exit 0; stdout='EXPOSED'; stderr='' | exit 0; stdout='BLOCKED'; stderr='' |
| read-shell:home/.config/secrets | PASS | configuration_outcome | exit 0; stdout='EXPOSED'; stderr='' | exit 20; stdout=''; stderr='cat: <temp>/home/.config/secrets/credentials: Operation not permitted' |
| read-python:home/.config/secrets | PASS | configuration_outcome | exit 0; stdout='EXPOSED'; stderr='' | exit 0; stdout='BLOCKED'; stderr='' |
| read-shell:protected | PASS | configuration_outcome | exit 0; stdout='EXPOSED'; stderr='' | exit 20; stdout=''; stderr='cat: <temp>/protected/marker.txt: Operation not permitted' |
| read-python:protected | PASS | configuration_outcome | exit 0; stdout='EXPOSED'; stderr='' | exit 0; stdout='BLOCKED'; stderr='' |
| read-symlink | PASS | configuration_outcome | exit 0; stdout='EXPOSED'; stderr='' | exit 20; stdout=''; stderr='cat: <temp>/work/protected-link: Operation not permitted' |
| write-config | PASS | configuration_outcome | exit 0; stdout='EXPOSED'; stderr='' | exit 0; stdout='BLOCKED'; stderr='' |
| write-outside | PASS | configuration_outcome | exit 0; stdout='EXPOSED'; stderr='' | exit 0; stdout='BLOCKED'; stderr='' |
| tcp-loopback | PASS | configuration_outcome | exit 0; stdout='EXPOSED'; stderr='' | exit 0; stdout='BLOCKED'; stderr='' |
| unix-socket | PASS | configuration_outcome | exit 0; stdout='EXPOSED'; stderr='' | exit 0; stdout='BLOCKED'; stderr='' |
| inherited-token | EXPECTED-VISIBLE | documented_behavior | exit 0; stdout='EXPOSED'; stderr='' | exit 0; stdout='EXPOSED'; stderr='' |
| filtered-token | PASS | configuration_outcome | exit 0; stdout='EXPOSED'; stderr='' | exit 0; stdout='BLOCKED'; stderr='' |
| dns-lookup | UNMEASURED | configuration_outcome | not run | network=false; external route probes require explicit external_routes=true policy opt-in |
| tcp-off-host | UNMEASURED | configuration_outcome | not run | network=false; external route probes require explicit external_routes=true policy opt-in |

## Not reachable without a model turn (UNMEASURED)

- claude permissions.deny Read()/Edit() merged into sandbox
- Claude Code protected paths (.claude, .mcp.json, .git hooks/config, ~/.claude)
- excludedCommands / allowUnsandboxedCommands / dangerouslyDisableSandbox retry
- CLAUDE_CODE_SUBPROCESS_ENV_SCRUB
- failIfUnavailable
- Read/Edit/WebFetch tools, hooks, MCP (outside sandbox by design)
- Claude Code bundled sandbox-runtime version (not exposed)
