# Keepout result: imported Codex profile

- Harness: `codex sandbox imported permission profile`
- CLI: `codex-cli 0.156.1`
- OS: `macOS-27.0.1-arm64-arm-64bit-Mach-O`
- Run time (UTC): `2026-10-03T17:31:37+00:00`
- Config: `KO020-fix.toml` sha256 `82b3d0c71d48d6aa5e3d82286f2ae164ef659773813b11674908cd55fc1f7e51` (fixture: `{R}` read as `/keepout-fixture-root`)
- Profile: `p`; extends chain: `p`
- Summary: controls passed; tested 11, untestable 1; PASS 4, FAIL 0, INVALID 0, UNMEASURED 8
- Run-wide omitted-rule control: PASS
- Seatbelt denial log (`--log-denials`, first denial probe): CAPTURED: `(bash) file-read-data <temp>/dir-shape/workspace; (bash) file-read-data <temp>/dir-shape; (cat) file-read-data <temp>/dir-shape/abs/private/tmp/keepout-canary`
- Dropped top-level keys (not carried into the generated config): none

Findings and results apply to codex-cli 0.156.1 on this macOS machine; none is a vendor vulnerability claim. `:minimal`'s /private/tmp read is documented-by-design platform defaults, reported because it defeats a common :root-deny intent.

Allowed actions run inside the sandbox first; every denial also needs an exposed unsandboxed control. If an allowed action fails, or the omitted-rule control cannot show exposure, every denial is INVALID.

## Remap (config path -> disposable path)

| Profile | Config path | Access | Disposable path |
| --- | --- | --- | --- |
| p | :root | deny | not remapped (token) |
| p | :minimal | read | not remapped (token) |
| p | /private/tmp | deny | <temp>/dir-shape/abs/private/tmp |

## Lint findings for this profile

- none

## Generated config (temporary paths redacted)

```toml
"default_permissions" = "p"
["permissions"."p"."filesystem"]
":root" = "deny"
":minimal" = "read"
"<temp>/dir-shape/abs/private/tmp" = "deny"
"/private/tmp" = "deny"
```

| Row | Verdict | Classification | Lint | Load-bearing | Control evidence | Sandbox evidence | Note |
| --- | --- | --- | --- | --- | --- | --- | --- |
| allowed:echo | PASS | configuration_outcome |  |  | not needed for allowed action | exit 0; stdout='EXPOSED'; stderr='' |  |
| token::root | UNMEASURED | configuration_outcome |  |  | not run | machine-wide token; Keepout never plants in real system paths |  |
| deny:/private/tmp[dir]:shell-read | PASS | configuration_outcome |  | false | exit 0; stdout='EXPOSED'; stderr='' | exit 20; stdout=''; stderr='shell-init: error retrieving current directory: getcwd: cannot access parent directories: Operation not permitted\njob-working-directory: error retrieving current directory: getcwd:' | real path is under /private/tmp; remapped result does not reflect :minimal coverage; also blocked without this rule (covered by base/broader deny) |
| deny:/private/tmp[dir]:python-read | UNMEASURED | configuration_outcome |  |  | exit 0; stdout='EXPOSED'; stderr='' | exit 71; stdout=''; stderr="sandbox-exec: execvp() of '/opt/homebrew/opt/python@3.14/bin/python3.14' failed: Operation not permitted" | real path is under /private/tmp; remapped result does not reflect :minimal coverage |
| deny:/private/tmp[dir]:write-new | UNMEASURED | configuration_outcome |  |  | exit 0; stdout='EXPOSED'; stderr='' | exit 71; stdout=''; stderr="sandbox-exec: execvp() of '/opt/homebrew/opt/python@3.14/bin/python3.14' failed: Operation not permitted" | real path is under /private/tmp; remapped result does not reflect :minimal coverage |
| deny:/private/tmp[file]:shell-read | PASS | configuration_outcome |  |  | exit 0; stdout='EXPOSED'; stderr='' | exit 20; stdout=''; stderr='shell-init: error retrieving current directory: getcwd: cannot access parent directories: Operation not permitted\njob-working-directory: error retrieving current directory: getcwd:' | real path is under /private/tmp; remapped result does not reflect :minimal coverage |
| deny:/private/tmp[file]:python-read | UNMEASURED | configuration_outcome |  |  | exit 0; stdout='EXPOSED'; stderr='' | exit 71; stdout=''; stderr="sandbox-exec: execvp() of '/opt/homebrew/opt/python@3.14/bin/python3.14' failed: Operation not permitted" | real path is under /private/tmp; remapped result does not reflect :minimal coverage |
| deny:/private/tmp[file]:overwrite | UNMEASURED | configuration_outcome |  |  | exit 0; stdout='EXPOSED'; stderr='' | exit 71; stdout=''; stderr="sandbox-exec: execvp() of '/opt/homebrew/opt/python@3.14/bin/python3.14' failed: Operation not permitted" | real path is under /private/tmp; remapped result does not reflect :minimal coverage |
| network:tcp-loopback | UNMEASURED | configuration_outcome |  |  | exit 0; stdout='EXPOSED'; stderr='' | exit 71; stdout=''; stderr="sandbox-exec: execvp() of '/opt/homebrew/opt/python@3.14/bin/python3.14' failed: Operation not permitted" |  |
| network:unix-socket | UNMEASURED | configuration_outcome |  |  | exit 0; stdout='EXPOSED'; stderr='' | exit 71; stdout=''; stderr="sandbox-exec: execvp() of '/opt/homebrew/opt/python@3.14/bin/python3.14' failed: Operation not permitted" |  |
| minimal-tmp-exposure:shell-read | PASS | configuration_outcome |  |  | exit 0; stdout='EXPOSED'; stderr='' | exit 20; stdout=''; stderr='shell-init: error retrieving current directory: getcwd: cannot access parent directories: Operation not permitted\njob-working-directory: error retrieving current directory: getcwd:' |  |
| minimal-tmp-exposure:python-read | UNMEASURED | configuration_outcome |  |  | exit 0; stdout='EXPOSED'; stderr='' | exit 71; stdout=''; stderr="sandbox-exec: execvp() of '/opt/homebrew/opt/python@3.14/bin/python3.14' failed: Operation not permitted" |  |
