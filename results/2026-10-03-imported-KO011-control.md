# Keepout result: imported Codex profile

- Harness: `codex sandbox imported permission profile`
- CLI: `codex-cli 0.156.1`
- OS: `macOS-27.0.1-arm64-arm-64bit-Mach-O`
- Run time (UTC): `2026-10-03T17:19:38+00:00`
- Config: `KO011-control.toml` sha256 `552a90982a01298948935b133495b5f5484c4ef9a3cec6d65a7c9cab5325e498` (fixture: `{R}` read as `/keepout-fixture-root`)
- Profile: `p`; extends chain: `p` -> `:read-only`
- Summary: controls passed; tested 4, untestable 0; PASS 4, FAIL 0, INVALID 0, UNMEASURED 0
- Run-wide omitted-rule control: PASS
- Seatbelt denial log (`--log-denials`, first denial probe): UNMEASURED: `no measured denial to capture`
- Dropped top-level keys (not carried into the generated config): none

Findings and results apply to codex-cli 0.156.1 on this macOS machine; none is a vendor vulnerability claim. `:minimal`'s /private/tmp read is documented-by-design platform defaults, reported because it defeats a common :root-deny intent.

Allowed actions run inside the sandbox first; every denial also needs an exposed unsandboxed control. If an allowed action fails, or the omitted-rule control cannot show exposure, every denial is INVALID.

## Remap (config path -> disposable path)

| Profile | Config path | Access | Disposable path |
| --- | --- | --- | --- |
| p | /keepout-fixture-root/work | write | <temp>/dir-shape/abs/keepout-fixture-root/work |

## Lint findings for this profile

- none

## Generated config (temporary paths redacted)

```toml
"default_permissions" = "p"
["permissions"."p"]
"extends" = ":read-only"

["permissions"."p"."network"]
"enabled" = true

["permissions"."p"."filesystem"]
"<temp>/dir-shape/abs/keepout-fixture-root/work" = "write"
```

| Row | Verdict | Classification | Lint | Load-bearing | Control evidence | Sandbox evidence | Note |
| --- | --- | --- | --- | --- | --- | --- | --- |
| allowed:echo | PASS | configuration_outcome |  |  | not needed for allowed action | exit 0; stdout='EXPOSED'; stderr='' |  |
| allowed:write:/keepout-fixture-root/work | PASS | configuration_outcome |  |  | not needed for allowed action | exit 0; stdout='EXPOSED'; stderr='' |  |
| network:tcp-loopback | PASS | configuration_outcome |  |  | not needed for allowed action | exit 0; stdout='EXPOSED'; stderr='' |  |
| network:unix-socket | PASS | configuration_outcome |  |  | not needed for allowed action | exit 0; stdout='EXPOSED'; stderr='' |  |
