# Keepout result

- Harness: `codex sandbox named permission profile`
- CLI: `codex-cli 0.156.1`
- OS: `macOS-27.0-arm64-arm-64bit-Mach-O`
- Run time (UTC): `2026-09-27T13:57:43+00:00`

A PASS requires the unsandboxed control to observe the exposure and the sandboxed probe to match the policy. INVALID means the control did not prove the probe. UNMEASURED means the sandbox result was inconclusive or the probe was not run.

| Check | Verdict | Control evidence | Sandbox evidence |
| --- | --- | --- | --- |
| read-shell:home/.ssh | PASS | exit 0; stdout='EXPOSED'; stderr='' | exit 20; stdout=''; stderr='cat: <temp>/home/.ssh/id_test: Operation not permitted' |
| read-python:home/.ssh | PASS | exit 0; stdout='EXPOSED'; stderr='' | exit 0; stdout='BLOCKED'; stderr='' |
| read-shell:home/.config/codex | PASS | exit 0; stdout='EXPOSED'; stderr='' | exit 20; stdout=''; stderr='cat: <temp>/home/.config/codex/settings.toml: Operation not permitted' |
| read-python:home/.config/codex | PASS | exit 0; stdout='EXPOSED'; stderr='' | exit 0; stdout='BLOCKED'; stderr='' |
| read-shell:home/.config/secrets | PASS | exit 0; stdout='EXPOSED'; stderr='' | exit 20; stdout=''; stderr='cat: <temp>/home/.config/secrets/credentials: Operation not permitted' |
| read-python:home/.config/secrets | PASS | exit 0; stdout='EXPOSED'; stderr='' | exit 0; stdout='BLOCKED'; stderr='' |
| read-shell:protected | PASS | exit 0; stdout='EXPOSED'; stderr='' | exit 20; stdout=''; stderr='cat: <temp>/protected/marker.txt: Operation not permitted' |
| read-python:protected | PASS | exit 0; stdout='EXPOSED'; stderr='' | exit 0; stdout='BLOCKED'; stderr='' |
| read-symlink | PASS | exit 0; stdout='EXPOSED'; stderr='' | exit 20; stdout=''; stderr='cat: <temp>/work/protected-link: Operation not permitted' |
| write-config | PASS | exit 0; stdout='EXPOSED'; stderr='' | exit 0; stdout='BLOCKED'; stderr='' |
| write-outside | PASS | exit 0; stdout='EXPOSED'; stderr='' | exit 0; stdout='BLOCKED'; stderr='' |
| tcp-loopback | PASS | exit 0; stdout='EXPOSED'; stderr='' | exit 0; stdout='BLOCKED'; stderr='' |
| unix-socket | PASS | exit 0; stdout='EXPOSED'; stderr='' | exit 0; stdout='BLOCKED'; stderr='' |
| inherited-token | FAIL | exit 0; stdout='EXPOSED'; stderr='' | exit 0; stdout='EXPOSED'; stderr='' |
| tcp-off-host | UNMEASURED | not run | off-host network access is disallowed for this run |
