# Keepout results

Each result applies only to the tested CLI version, policy, machine and routes. It is not a security certification and does not establish a vendor vulnerability.

Keepout results — 3 runs, generated from 3 files.

| check | codex 0.156.1 macOS 27.0 2026-09-27 | codex 0.156.1 macOS 27.0.1 2026-10-03 |
| --- | --- | --- |
| controls: allowed actions | PASS | PASS |
| controls: omitted-rule fail-closed | PASS | PASS |
| run status | controls passed | controls passed |
| allowed-read | PASS | PASS |
| allowed-write | PASS | PASS |
| allowed-command | PASS | PASS |
| read-shell:home/.ssh | PASS | PASS |
| read-python:home/.ssh | PASS | PASS |
| read-shell:home/.config/codex | PASS | PASS |
| read-python:home/.config/codex | PASS | PASS |
| read-shell:home/.config/secrets | PASS | PASS |
| read-python:home/.config/secrets | PASS | PASS |
| read-shell:protected | PASS | PASS |
| read-python:protected | PASS | PASS |
| read-symlink | PASS | PASS |
| write-config | PASS | PASS |
| write-outside | PASS | PASS |
| tcp-loopback | PASS | PASS |
| unix-socket | PASS | PASS |
| inherited-token | EXPECTED-VISIBLE | EXPECTED-VISIBLE |
| filtered-token | PASS | PASS |
| dns-lookup | UNMEASURED | UNMEASURED |
| tcp-off-host | UNMEASURED | UNMEASURED |

## Runs

- `2026-09-27b-macos-codex-0.156.1.json`; harness: codex sandbox named permission profile; CLI: codex-cli 0.156.1; OS: macOS-27.0-arm64-arm-64bit-Mach-O; date: 2026-09-27T14:21:23+00:00; status: controls passed; generated network mode: limited; held: 0
- `2026-10-03-macos-codex-0.156.1.json`; harness: codex sandbox named permission profile; CLI: codex-cli 0.156.1; OS: macOS-27.0.1-arm64-arm-64bit-Mach-O; date: 2026-10-03T16:46:50+00:00; status: controls passed; generated network mode: limited; held: 0

## Evidence

<details>
<summary>codex 0.156.1 macOS 27.0 2026-09-27</summary>

| check | verdict | classification | control evidence | sandbox evidence |
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

</details>

<details>
<summary>codex 0.156.1 macOS 27.0.1 2026-10-03</summary>

| check | verdict | classification | control evidence | sandbox evidence |
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

</details>

## History

- `2026-09-27-macos-codex-0.156.1.json` (codex 0.156.1 macOS 27.0 2026-09-27): The inherited-token FAIL label is superseded by round 2 EXPECTED-VISIBLE: this run injected a fake token without an environment filter, and file/network sandbox rules do not promise to remove inherited variables. Status: legacy run: allowed-action and omitted-rule controls not recorded; denials not control-validated.
