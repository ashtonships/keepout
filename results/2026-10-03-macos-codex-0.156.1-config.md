# Keepout result: imported Codex profile

- Harness: `codex sandbox imported permission profile`
- CLI: `codex-cli 0.156.1`
- OS: `macOS-27.0.1-arm64-arm-64bit-Mach-O`
- Run time (UTC): `2026-10-03T17:19:09+00:00`
- Config: `2026-09-26-failure-modes.toml` sha256 `ba4e8b2e574cff42cbba272142d85e7990799a042e03f08ee515f28fc4a9777a` (fixture: `{R}` read as `/keepout-fixture-root`)
- Profile: `worker`; extends chain: `worker` -> `base` -> `:read-only`
- Summary: controls passed; tested 48, untestable 5; PASS 44, FAIL 4, INVALID 0, UNMEASURED 5
- Run-wide omitted-rule control: PASS
- Seatbelt denial log (`--log-denials`, first denial probe): CAPTURED: `(cat) file-read-data <temp>/dir-shape/home/.ssh/keepout-canary`
- Dropped top-level keys (not carried into the generated config): `mcp_servers`, `model`, `sandbox_mode`, `sandbox_permissions`

Findings and results apply to codex-cli 0.156.1 on this macOS machine; none is a vendor vulnerability claim. `:minimal`'s /private/tmp read is documented-by-design platform defaults, reported because it defeats a common :root-deny intent.

Allowed actions run inside the sandbox first; every denial also needs an exposed unsandboxed control. If an allowed action fails, or the omitted-rule control cannot show exposure, every denial is INVALID.

## Remap (config path -> disposable path)

| Profile | Config path | Access | Disposable path |
| --- | --- | --- | --- |
| base | ~/.ssh | deny | <temp>/dir-shape/home/.ssh |
| base | ~/.kaggle | deny | <temp>/dir-shape/home/.kaggle |
| base | ~/.codex/auth.json | deny | <temp>/dir-shape/home/.codex/auth.json |
| base | ~/.config/opportunity-engine | deny | <temp>/dir-shape/home/.config/opportunity-engine |
| worker | /.../engine/.auth | read | <temp>/dir-shape/abs/.../engine/.auth |
| base | /.../work/projects | write | <temp>/dir-shape/abs/.../work/projects |
| base | /.../demo/.git | read | <temp>/dir-shape/abs/.../demo/.git |
| worker | /.../engine/keys | deny | <temp>/dir-shape/abs/.../engine/keys |
| worker | /.../keys/cache | write | <temp>/dir-shape/abs/.../keys/cache |
| worker | :home | deny | not remapped (token) |
| worker | /tmp/engine-keys | deny | <temp>/dir-shape/abs/.../tmp/engine-keys |
| worker | /.../**/*.env | deny | <temp>/dir-shape/abs/.../**/*.env |

## Lint findings for this profile

- KO002 high: `sandbox_permissions` is ignored by Codex 0.156.1
- KO011 high: network.mode = "limited" is ignored; networking stays as if unset
- KO011 high: network.mode = "full" is ignored; networking stays as if unset
- KO024 high: profile `worker` sets `{R}/engine/.auth` = read, removing `base`'s deny
- KO013 high: token `:home` is not recognized and will be ignored
- KO040 medium: `sandbox_mode` is set alongside default_permissions
- KO022 medium: `{R}/engine/keys/cache` (write) is inside denied `{R}/engine/keys`; that subtree is open again
- KO031 info: `~/.ssh` resolves against the Codex process's $HOME
- KO031 info: `~/.kaggle` resolves against the Codex process's $HOME
- KO031 info: `~/.codex/auth.json` resolves against the Codex process's $HOME
- KO031 info: `~/.config/opportunity-engine` resolves against the Codex process's $HOME
- KO030 info: `/tmp/engine-keys` is canonically `/.../tmp/engine-keys`

## Generated config (temporary paths redacted)

```toml
"default_permissions" = "worker"
["permissions"."worker"]
"extends" = "base"

["permissions"."worker"."network"]
"mode" = "full"

["permissions"."worker"."filesystem"]
"<temp>/dir-shape/abs/.../engine/.auth" = "read"
"<temp>/dir-shape/abs/.../engine/keys" = "deny"
"<temp>/dir-shape/abs/.../keys/cache" = "write"
":home" = "deny"
"<temp>/dir-shape/abs/.../tmp/engine-keys" = "deny"
"<temp>/dir-shape/abs/.../**/*.env" = "deny"

["permissions"."base"]
"extends" = ":read-only"

["permissions"."base"."network"]
"mode" = "limited"

["permissions"."base"."filesystem"]
"~/.ssh" = "deny"
"~/.kaggle" = "deny"
"~/.codex/auth.json" = "deny"
"~/.config/opportunity-engine" = "deny"
"<temp>/dir-shape/abs/.../engine/.auth" = "deny"
"<temp>/dir-shape/abs/.../work/projects" = "write"
"<temp>/dir-shape/abs/.../demo/.git" = "read"
```

| Row | Verdict | Classification | Lint | Load-bearing | Control evidence | Sandbox evidence | Note |
| --- | --- | --- | --- | --- | --- | --- | --- |
| allowed:echo | PASS | configuration_outcome |  |  | not needed for allowed action | exit 0; stdout='EXPOSED'; stderr='' |  |
| allowed:read:/.../engine/.auth | PASS | configuration_outcome |  |  | not needed for allowed action | exit 0; stdout='EXPOSED'; stderr='' |  |
| read-only:/.../engine/.auth:write-new | PASS | configuration_outcome |  |  | exit 0; stdout='EXPOSED'; stderr='' | exit 0; stdout='BLOCKED'; stderr='' |  |
| allowed:write:/.../work/projects | PASS | configuration_outcome |  |  | not needed for allowed action | exit 0; stdout='EXPOSED'; stderr='' |  |
| allowed:read:/.../demo/.git | PASS | configuration_outcome |  |  | not needed for allowed action | exit 0; stdout='EXPOSED'; stderr='' |  |
| read-only:/.../demo/.git:write-new | PASS | configuration_outcome |  |  | exit 0; stdout='EXPOSED'; stderr='' | exit 0; stdout='BLOCKED'; stderr='' |  |
| allowed:write:/.../keys/cache | PASS | configuration_outcome |  |  | not needed for allowed action | exit 0; stdout='EXPOSED'; stderr='' |  |
| deny:~/.ssh[dir]:shell-read | PASS | configuration_outcome |  | true | exit 0; stdout='EXPOSED'; stderr='' | exit 20; stdout=''; stderr='cat: <temp>/dir-shape/home/.ssh/keepout-canary: Operation not permitted' |  |
| deny:~/.ssh[dir]:python-read | PASS | configuration_outcome |  |  | exit 0; stdout='EXPOSED'; stderr='' | exit 0; stdout='BLOCKED'; stderr='' |  |
| deny:~/.ssh[dir]:write-new | PASS | configuration_outcome |  |  | exit 0; stdout='EXPOSED'; stderr='' | exit 0; stdout='BLOCKED'; stderr='' |  |
| deny:~/.ssh[file]:shell-read | PASS | configuration_outcome |  |  | exit 0; stdout='EXPOSED'; stderr='' | exit 20; stdout=''; stderr='cat: <temp>/file-shape/home/.ssh: Operation not permitted' |  |
| deny:~/.ssh[file]:python-read | PASS | configuration_outcome |  |  | exit 0; stdout='EXPOSED'; stderr='' | exit 0; stdout='BLOCKED'; stderr='' |  |
| deny:~/.ssh[file]:overwrite | PASS | configuration_outcome |  |  | exit 0; stdout='EXPOSED'; stderr='' | exit 0; stdout='BLOCKED'; stderr='' |  |
| deny:~/.kaggle[dir]:shell-read | PASS | configuration_outcome |  | true | exit 0; stdout='EXPOSED'; stderr='' | exit 20; stdout=''; stderr='cat: <temp>/dir-shape/home/.kaggle/keepout-canary: Operation not permitted' |  |
| deny:~/.kaggle[dir]:python-read | PASS | configuration_outcome |  |  | exit 0; stdout='EXPOSED'; stderr='' | exit 0; stdout='BLOCKED'; stderr='' |  |
| deny:~/.kaggle[dir]:write-new | PASS | configuration_outcome |  |  | exit 0; stdout='EXPOSED'; stderr='' | exit 0; stdout='BLOCKED'; stderr='' |  |
| deny:~/.kaggle[file]:shell-read | PASS | configuration_outcome |  |  | exit 0; stdout='EXPOSED'; stderr='' | exit 20; stdout=''; stderr='cat: <temp>/file-shape/home/.kaggle: Operation not permitted' |  |
| deny:~/.kaggle[file]:python-read | PASS | configuration_outcome |  |  | exit 0; stdout='EXPOSED'; stderr='' | exit 0; stdout='BLOCKED'; stderr='' |  |
| deny:~/.kaggle[file]:overwrite | PASS | configuration_outcome |  |  | exit 0; stdout='EXPOSED'; stderr='' | exit 0; stdout='BLOCKED'; stderr='' |  |
| deny:~/.codex/auth.json[dir]:shell-read | PASS | configuration_outcome |  | true | exit 0; stdout='EXPOSED'; stderr='' | exit 20; stdout=''; stderr='cat: <temp>/dir-shape/home/.codex/auth.json/keepout-canary: Operation not permitted' |  |
| deny:~/.codex/auth.json[dir]:python-read | PASS | configuration_outcome |  |  | exit 0; stdout='EXPOSED'; stderr='' | exit 0; stdout='BLOCKED'; stderr='' |  |
| deny:~/.codex/auth.json[dir]:write-new | PASS | configuration_outcome |  |  | exit 0; stdout='EXPOSED'; stderr='' | exit 0; stdout='BLOCKED'; stderr='' |  |
| deny:~/.codex/auth.json[file]:shell-read | PASS | configuration_outcome |  |  | exit 0; stdout='EXPOSED'; stderr='' | exit 20; stdout=''; stderr='cat: <temp>/file-shape/home/.codex/auth.json: Operation not permitted' |  |
| deny:~/.codex/auth.json[file]:python-read | PASS | configuration_outcome |  |  | exit 0; stdout='EXPOSED'; stderr='' | exit 0; stdout='BLOCKED'; stderr='' |  |
| deny:~/.codex/auth.json[file]:overwrite | PASS | configuration_outcome |  |  | exit 0; stdout='EXPOSED'; stderr='' | exit 0; stdout='BLOCKED'; stderr='' |  |
| deny:~/.config/opportunity-engine[dir]:shell-read | PASS | configuration_outcome |  | true | exit 0; stdout='EXPOSED'; stderr='' | exit 20; stdout=''; stderr='cat: <temp>/dir-shape/home/.config/opportunity-engine/keepout-canary: Operation not permitted' |  |
| deny:~/.config/opportunity-engine[dir]:python-read | PASS | configuration_outcome |  |  | exit 0; stdout='EXPOSED'; stderr='' | exit 0; stdout='BLOCKED'; stderr='' |  |
| deny:~/.config/opportunity-engine[dir]:write-new | PASS | configuration_outcome |  |  | exit 0; stdout='EXPOSED'; stderr='' | exit 0; stdout='BLOCKED'; stderr='' |  |
| deny:~/.config/opportunity-engine[file]:shell-read | PASS | configuration_outcome |  |  | exit 0; stdout='EXPOSED'; stderr='' | exit 20; stdout=''; stderr='cat: <temp>/file-shape/home/.config/opportunity-engine: Operation not permitted' |  |
| deny:~/.config/opportunity-engine[file]:python-read | PASS | configuration_outcome |  |  | exit 0; stdout='EXPOSED'; stderr='' | exit 0; stdout='BLOCKED'; stderr='' |  |
| deny:~/.config/opportunity-engine[file]:overwrite | PASS | configuration_outcome |  |  | exit 0; stdout='EXPOSED'; stderr='' | exit 0; stdout='BLOCKED'; stderr='' |  |
| deny:/.../engine/keys[dir]:shell-read | PASS | configuration_outcome |  | true | exit 0; stdout='EXPOSED'; stderr='' | exit 20; stdout=''; stderr='cat: <temp>/dir-shape/abs/.../engine/keys/keepout-canary: Operation not permitted' |  |
| deny:/.../engine/keys[dir]:python-read | PASS | configuration_outcome |  |  | exit 0; stdout='EXPOSED'; stderr='' | exit 0; stdout='BLOCKED'; stderr='' |  |
| deny:/.../engine/keys[dir]:write-new | PASS | configuration_outcome |  |  | exit 0; stdout='EXPOSED'; stderr='' | exit 0; stdout='BLOCKED'; stderr='' |  |
| deny:/.../engine/keys[file]:shell-read | UNMEASURED | configuration_outcome |  |  | not run | other entries sit inside this path; it cannot be a file |  |
| deny:/.../engine/keys[file]:python-read | UNMEASURED | configuration_outcome |  |  | not run | other entries sit inside this path; it cannot be a file |  |
| deny:/.../engine/keys[file]:overwrite | UNMEASURED | configuration_outcome |  |  | not run | other entries sit inside this path; it cannot be a file |  |
| token::home | UNMEASURED | configuration_outcome | KO013 |  | not run | unknown token; Codex 0.156.1 ignores it (KO013) |  |
| ignored-token::home:shell-read | FAIL | configuration_outcome | KO013 |  | exit 0; stdout='EXPOSED'; stderr='' | exit 0; stdout='EXPOSED'; stderr='' |  |
| deny:/tmp/engine-keys[dir]:shell-read | PASS | configuration_outcome | KO030 | true | exit 0; stdout='EXPOSED'; stderr='' | exit 20; stdout=''; stderr='cat: <temp>/dir-shape/abs/.../tmp/engine-keys/keepout-canary: Operation not permitted' | real path is under /private/tmp; remapped result does not reflect :minimal coverage |
| deny:/tmp/engine-keys[dir]:python-read | PASS | configuration_outcome | KO030 |  | exit 0; stdout='EXPOSED'; stderr='' | exit 0; stdout='BLOCKED'; stderr='' | real path is under /private/tmp; remapped result does not reflect :minimal coverage |
| deny:/tmp/engine-keys[dir]:write-new | PASS | configuration_outcome | KO030 |  | exit 0; stdout='EXPOSED'; stderr='' | exit 0; stdout='BLOCKED'; stderr='' | real path is under /private/tmp; remapped result does not reflect :minimal coverage |
| deny:/tmp/engine-keys[file]:shell-read | PASS | configuration_outcome | KO030 |  | exit 0; stdout='EXPOSED'; stderr='' | exit 20; stdout=''; stderr='cat: <temp>/file-shape/abs/.../tmp/engine-keys: Operation not permitted' | real path is under /private/tmp; remapped result does not reflect :minimal coverage |
| deny:/tmp/engine-keys[file]:python-read | PASS | configuration_outcome | KO030 |  | exit 0; stdout='EXPOSED'; stderr='' | exit 0; stdout='BLOCKED'; stderr='' | real path is under /private/tmp; remapped result does not reflect :minimal coverage |
| deny:/tmp/engine-keys[file]:overwrite | PASS | configuration_outcome | KO030 |  | exit 0; stdout='EXPOSED'; stderr='' | exit 0; stdout='BLOCKED'; stderr='' | real path is under /private/tmp; remapped result does not reflect :minimal coverage |
| glob:/.../**/*.env:planted:shell-read | PASS | configuration_outcome |  |  | exit 0; stdout='EXPOSED'; stderr='' | exit 20; stdout=''; stderr='cat: <temp>/dir-shape/abs/.../work/projects/kd1/kd2/keepout.env: Operation not permit' |  |
| glob:/.../**/*.env:created-in-sandbox | PASS | configuration_outcome |  |  | exit 0; stdout='EXPOSED'; stderr='' | exit 0; stdout='BLOCKED'; stderr='' |  |
| overridden:base:/.../engine/.auth | UNMEASURED | configuration_outcome |  |  | not run | replaced by child profile entry, see KO024 |  |
| extends-relax:/.../engine/.auth:shell-read | FAIL | configuration_outcome | KO024 |  | exit 0; stdout='EXPOSED'; stderr='' | exit 0; stdout='EXPOSED'; stderr='' |  |
| carve-out:/.../keys/cache:write-new | FAIL | configuration_outcome | KO022 |  | exit 0; stdout='EXPOSED'; stderr='' | exit 0; stdout='EXPOSED'; stderr='' |  |
| network:tcp-loopback | PASS | configuration_outcome |  |  | exit 0; stdout='EXPOSED'; stderr='' | exit 0; stdout='BLOCKED'; stderr='' |  |
| network:unix-socket | PASS | configuration_outcome |  |  | exit 0; stdout='EXPOSED'; stderr='' | exit 0; stdout='BLOCKED'; stderr='' |  |
| ignored-network-key:tcp-loopback | FAIL | configuration_outcome | KO011 |  | exit 0; stdout='EXPOSED'; stderr='' | exit 0; stdout='BLOCKED'; stderr=''; written intent was allow |  |

## Known configuration outcomes (measurement receipts)

- `ignored-token::home:shell-read` (KO013): 2026-10-03: ":home"="deny" left a canary under the fake HOME EXPOSED with empty stderr under `codex sandbox`; `codex exec` warned 'Configured filesystem path `:home` is not recognized'.
- `extends-relax:/.../engine/.auth:shell-read` (KO024): 2026-10-03 C7: [permissions.p] denies {R}/protected; [permissions.c] extends p and sets it to read; `-P c` gave EXPOSED. C6 (no override) gave BLOCKED.
- `carve-out:/.../keys/cache:write-new` (KO022): 2026-10-03 O2: deny {R}/prot plus write {R}/prot/inner: inner read and write both succeeded while the parent file stayed BLOCKED (more specific rule wins).
- `ignored-network-key:tcp-loopback` (KO011): 2026-10-03: loopback TCP under `codex sandbox -P p` was BLOCKED for mode="full", mode="limited", enabled=false and no key; only enabled=true gave EXPOSED (:read-only and :workspace alike).
