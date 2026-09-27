# Keepout result

- Harness: `codex sandbox named permission profile`
- CLI: `codex-cli 0.156.1`
- OS: `macOS-27.0-arm64-arm-64bit-Mach-O`
- Run time (UTC): `2026-09-27T14:21:23+00:00`
- Summary: controls passed; PASS 17, FAIL 0, INVALID 0, UNMEASURED 2, EXPECTED-VISIBLE 1; enforcement failures 0
- Generated network mode: `limited`
- Effective profile readback: unavailable: codex sandbox 0.156.1 has no effective-profile display
- Strict config: rejected: --strict-config is not supported for codex sandbox
- Omitted-rule fail-closed check: PASS (probe without rule: FAIL)
- Omitted-rule -c override: `permissions.keepout={ extends = ":read-only", network = { mode = "limited" }, filesystem = { "<temp>/home/.config/codex" = "deny", "<temp>/home/.config/secrets" = "deny", "<temp>/protected" = "deny", "<temp>/work" = "write" } }`

Allowed-action controls run inside the sandbox. A denial PASS also requires an exposed unsandboxed control. If any allowed action fails, all denial verdicts are INVALID.

## Generated -c overrides (temporary paths redacted)

- `permissions.keepout={ extends = ":read-only", network = { mode = "limited" }, filesystem = { "<temp>/home/.ssh" = "deny", "<temp>/home/.config/codex" = "deny", "<temp>/home/.config/secrets" = "deny", "<temp>/protected" = "deny", "<temp>/work" = "write" } }`
- `shell_environment_policy.inherit=none`
- Environment override scope: filtered-token only

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
