"""Policy lint for an existing Codex config: `python3 -m keepout lint CONFIG [--profile NAME] [--json FILE]`.

Static by default. `--codex-check` is the only mode that runs Codex: a session start against a dead local provider
(127.0.0.1:9) in a fake CODEX_HOME with a sanitized copy of the permission settings, so no model turn is possible.
"""

from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
from typing import Callable

from . import codexconfig as cc
from .codexconfig import CodexConfig, ConfigError, Entry, ResolvedProfile

SEVERITIES = ("error", "high", "medium", "info")


@dataclass(frozen=True)
class Rule:
    severity: str
    title: str
    why: str
    fix: str
    measured: bool


RULES: dict[str, Rule] = {
    "KO001": Rule("error", "Config does not parse", "Codex refuses to start (measured: 'duplicate key').",
                  "Fix the TOML syntax; each key may appear once per table.", True),
    "KO002": Rule("high", "Ignored top-level sandbox key",
                  "ignored: silent under `codex sandbox`; `codex exec` warns '`sandbox_permissions` is ignored'.",
                  "Express it as a [permissions.<name>] profile and set default_permissions.", True),
    "KO003": Rule("info", "Unrecognized top-level key",
                  "not in Keepout's 0.156.1 key list; confirm with --codex-check.",
                  "Check the spelling against the Codex config reference.", False),
    "KO010": Rule("high", "Unknown key inside a permissions profile",
                  "silently ignored, even with `codex exec --strict-config` (measured).",
                  "Use only extends, description, filesystem, network, workspace_roots.", True),
    "KO011": Rule("high", "network.mode is ignored",
                  "ignored: mode=\"full\" did not enable networking (measured; only enabled=true did).",
                  "Write `network = { enabled = true }` or `{ enabled = false }`.", True),
    "KO012": Rule("high", "Unknown network key",
                  "silently ignored; the network rule you meant is not applied (measured for unknown keys).",
                  "Use enabled, domains, allow_local_binding or unix_sockets.", True),
    "KO013": Rule("high", "Unknown special path token",
                  "`codex sandbox` silently ignores it; exec warns 'not recognized ... will be ignored' (measured).",
                  "Use :root, :minimal, :workspace_roots, :tmpdir or :slash_tmp, or an absolute/~/ path.", True),
    "KO014": Rule("error", "Invalid filesystem access value",
                  "Codex refuses the config: 'did not match any variant of untagged enum "
                  "FilesystemPermissionToml' (measured; values are case-sensitive).",
                  "Use read, write or deny (lower case).", True),
    "KO015": Rule("info", "Undocumented value `none`",
                  "accepted and denies reads (measured), but undocumented; it may change.", "Use `deny`.", True),
    "KO016": Rule("error", "Relative filesystem path",
                  "Codex refuses it: 'must be absolute, use `~/...`, or start with `:`' (measured).",
                  "Write an absolute path, a ~/ path or a :token.", True),
    "KO020": Rule("high", ":minimal exposes /private/tmp",
                  "`:minimal` makes /private/tmp readable on macOS. A planted /private/tmp file was readable despite "
                  "`:root`=deny (measured).",
                  "Add `\"/private/tmp\" = \"deny\"` (measured to close it) or keep secrets out of /tmp.", True),
    "KO021": Rule("high", ":root denied with no :minimal",
                  "commands exit 134 before running (measured); the profile is unusable, not protective.",
                  "Add `\":minimal\" = \"read\"` (and see KO020) or extend :read-only.", True),
    "KO022": Rule("medium", "Allow rule inside a deny",
                  "more specific wins; the subtree is readable and writable again (measured).",
                  "Move the allowed folder outside the denied one, or drop the inner rule.", True),
    "KO023": Rule("info", "Same path both denied and allowed",
                  "deny wins (measured), so the other entry is dead.", "Remove the dead entry.", True),
    "KO024": Rule("high", "Child profile relaxes a parent deny",
                  "a child entry with the same path replaces the parent's; the parent deny is removed (measured).",
                  "Keep the deny in the child, or use a different (deeper) path for the child's allowance.", True),
    "KO030": Rule("info", "Non-canonical path",
                  "canonicalized by 0.156.1, for both existing and not-yet-created paths (measured); write it "
                  "canonically so older or newer versions and reviewers agree.",
                  "Write the canonical path.", True),
    "KO031": Rule("info", "~/ path depends on $HOME",
                  "resolves against the Codex process's $HOME (measured), so it moves when Codex runs under another "
                  "HOME (launchd, sudo).", "Use an absolute path when the HOME may differ.", True),
    "KO040": Rule("medium", "Legacy sandbox_mode next to default_permissions",
                  "the config sandbox_mode is silently ignored, yet `-s` on the command line overrides the profile "
                  "(measured). Docs: they cannot coexist.",
                  "Remove sandbox_mode/sandbox_workspace_write and never pass -s.", True),
    "KO041": Rule("error", "[permissions] without default_permissions",
                  "`codex exec` refuses to start, while `codex sandbox -P` still works (measured).",
                  "Set default_permissions to one of your profiles.", True),
    "KO042": Rule("error", "Undefined profile named",
                  "Codex refuses: 'refers to undefined profile' (measured).", "Name a defined profile.", True),
    "KO043": Rule("error", "Bad extends",
                  "Codex refuses an unsupported built-in (':readonly' measured) or an undefined parent; a cycle "
                  "cannot resolve.", "Extend :read-only, :workspace, :danger-full-access or a defined profile.", True),
    "KO050": Rule("info", "Extends :workspace",
                  "the :workspace built-in also grants writes to /tmp and $TMPDIR (measured banner).",
                  "Extend :read-only and grant the folders you need.", True),
    "KO051": Rule("info", "Network enabled for every domain",
                  "a `*` or `**.` domain allows any host (doc-only).", "List the domains you need.", False),
    "KO090": Rule("medium", "Codex reported a config message",
                  "Codex printed this during a dead-provider session start (--codex-check).",
                  "Read Codex's message.", True),
}


def finding(rule_id: str, cfg_path: str, line: int | None = None, profile: str | None = None,
            path: str | None = None, message: str = "") -> dict:
    rule = RULES[rule_id]
    return {
        "id": rule_id,
        "severity": rule.severity,
        "title": rule.title,
        "message": message or rule.title,
        "why": rule.why,
        "fix": rule.fix,
        "file": cfg_path,
        "line": line,
        "profile": profile,
        "path": path,
        "measured": cc.MEASURED if rule.measured else None,
        "evidence_fixture": f"tests/fixtures/lint/{rule_id}.toml",
    }


def lint_file(path: str | Path, profile: str | None = None, i_own_this_file: bool = False) -> list[dict]:
    try:
        cfg = cc.load_codex_config(path, i_own_this_file)
    except ConfigError as exc:
        hint = " (duplicate key)" if "overwrite" in str(exc) else ""
        return [finding("KO001", str(path), exc.line, message=f"TOML parse error{hint}: {exc}")]
    return lint(cfg, profile)


def lint(cfg: CodexConfig, profile: str | None = None) -> list[dict]:
    out: list[dict] = []
    p = cfg.path
    data = cfg.data
    for key in data:
        line = cc.find_line(cfg.text, key)
        if key in cc.KNOWN_IGNORED_TOP:
            out.append(finding("KO002", p, line, path=key, message=f"`{key}` is ignored by Codex 0.156.1"))
        elif key not in cc.KNOWN_TOP:
            out.append(finding("KO003", p, line, path=key, message=f"`{key}` is not a known top-level key"))
    default = data.get("default_permissions")
    has_permissions = isinstance(data.get("permissions"), dict)
    if default is not None and ("sandbox_mode" in data or "sandbox_workspace_write" in data):
        key = "sandbox_mode" if "sandbox_mode" in data else "sandbox_workspace_write"
        out.append(finding("KO040", p, cc.find_line(cfg.text, key), path=key,
                           message=f"`{key}` is set alongside default_permissions"))
    if has_permissions and default is None:
        out.append(finding("KO041", p, cc.find_line(cfg.text, "[permissions"),
                           message="[permissions] profiles defined but default_permissions is not set"))
    for label, name in (("default_permissions", default), ("--profile", profile)):
        if isinstance(name, str) and name not in cfg.profiles and name not in cc.BUILTINS:
            line = cc.find_line(cfg.text, "default_permissions") if label == "default_permissions" else None
            out.append(finding("KO042", p, line, profile=name, message=f"{label} names undefined profile `{name}`"))
    if profile is not None and profile not in cfg.profiles:
        return _sorted(out)
    names = list(cfg.profiles)
    if profile is not None:
        try:
            names = [item for item in cc.chain(cfg, profile) if item in cfg.profiles]
        except ConfigError:
            names = [profile]
    for name in names:
        out.extend(_lint_raw(cfg, cfg.profiles[name]))
    resolvable = [profile] if profile is not None else list(cfg.profiles)
    for name in resolvable:
        try:
            resolved = cc.resolve(cfg, name)
        except ConfigError as exc:
            out.append(finding("KO043", p, cfg.profiles[name].line, profile=name, message=str(exc)))
            continue
        out.extend(_lint_resolved(cfg, resolved))
    return _sorted(_dedupe(out))


def _lint_raw(cfg: CodexConfig, prof: cc.Profile) -> list[dict]:
    p, out, start = cfg.path, [], (prof.line or 1) - 1
    for key in prof.keys:
        if key not in cc.PROFILE_KEYS:
            out.append(finding("KO010", p, cc.find_line(cfg.text, key, start), prof.name, key,
                               f"`{key}` in [permissions.{prof.name}] is silently ignored"))
    for key, value in prof.network.items():
        line = cc.find_line(cfg.text, key, start)
        if key == "mode":
            out.append(finding("KO011", p, line, prof.name, "network.mode",
                               f"network.mode = {json.dumps(value)} is ignored; networking stays as if unset"))
        elif key not in cc.NETWORK_KEYS:
            out.append(finding("KO012", p, line, prof.name, f"network.{key}", f"network.{key} is ignored"))
    for entry in prof.filesystem:
        out.extend(_lint_entry(cfg, entry))
    return out


def _lint_entry(cfg: CodexConfig, entry: Entry) -> list[dict]:
    p, out = cfg.path, []
    shown = entry.label.replace(cc.FIXTURE_ROOT, cc.FIXTURE_PLACEHOLDER)
    if entry.scope == "token" and entry.path not in cc.TOKENS:
        out.append(finding("KO013", p, entry.line, entry.profile, entry.path,
                           f"token `{entry.path}` is not recognized and will be ignored"))
    if entry.access != "table":
        if not isinstance(entry.access, str) or entry.access not in cc.VALUES | cc.UNDOCUMENTED_VALUES:
            out.append(finding("KO014", p, entry.line, entry.profile, entry.path,
                               f"`{shown}` = {json.dumps(entry.access)} is not read, write or deny"))
        elif entry.access in cc.UNDOCUMENTED_VALUES:
            out.append(finding("KO015", p, entry.line, entry.profile, entry.path,
                               f"`{shown}` = \"none\" is undocumented"))
    if entry.scope == "relative":
        out.append(finding("KO016", p, entry.line, entry.profile, entry.path, f"`{shown}` is a relative path"))
    if entry.scope in ("abs", "home") and cc.normalize(entry.path) != entry.path:
        out.append(finding("KO030", p, entry.line, entry.profile, entry.path,
                           f"`{shown}` is canonically `{cc.normalize(entry.path).replace(cc.FIXTURE_ROOT, cc.FIXTURE_PLACEHOLDER)}`"))
    if entry.scope == "home":
        out.append(finding("KO031", p, entry.line, entry.profile, entry.path,
                           f"`{shown}` resolves against the Codex process's $HOME"))
    return out


def read_base(resolved: ResolvedProfile) -> bool:
    root = resolved.access(":root")
    if "deny" in root:
        return False
    return bool(resolved.base) or any(item in ("read", "write") for item in root)


def minimal_tmp_exposed(resolved: ResolvedProfile) -> bool:
    """The KO020 condition (pure, on the resolved profile)."""
    root_deny = "deny" in resolved.access(":root")
    minimal = any(item in ("read", "write") for item in resolved.access(":minimal"))
    tmp_denied = any(entry.scope == "abs" and entry.access in ("deny", "none") and not cc.is_glob(entry.path)
                     and cc.covers(cc.normalize(entry.path), "/private/tmp") and cc.normalize(entry.path) != "/"
                     for entry in resolved.filesystem)
    return (root_deny or not read_base(resolved)) and minimal and not tmp_denied


def _lint_resolved(cfg: CodexConfig, resolved: ResolvedProfile) -> list[dict]:
    p, out, name = cfg.path, [], resolved.name
    entries = [entry for entry in resolved.filesystem if entry.access != "table"]
    first = next((entry for entry in entries if entry.path == ":root"), None)
    if minimal_tmp_exposed(resolved):
        minimal = next(entry for entry in entries if entry.path == ":minimal")
        out.append(finding("KO020", p, minimal.line, name, ":minimal",
                           "`:minimal` with no read base and no /private/tmp deny leaves /private/tmp readable"))
    if "deny" in resolved.access(":root") and not resolved.access(":minimal"):
        out.append(finding("KO021", p, first.line if first else None, name, ":root",
                           "`:root` = deny with no `:minimal`: commands cannot start"))
    denies = [e for e in entries if e.access in ("deny", "none") and e.scope != "token" and not cc.is_glob(e.path)]
    allows = [e for e in entries if e.access in ("read", "write") and e.scope != "token"]
    for deny in denies:
        outer = cc.normalize(deny.path)
        for allow in allows:
            if allow.scope != deny.scope:
                continue
            inner = cc.normalize(allow.path)
            if inner != outer and cc.covers(outer, inner):
                out.append(finding("KO022", p, allow.line, name, allow.path,
                                   f"`{_show(allow.path)}` ({allow.access}) is inside denied `{_show(deny.path)}`; "
                                   "that subtree is open again"))
            elif inner == outer:
                out.append(finding("KO023", p, allow.line, name, allow.path,
                                   f"`{_show(allow.path)}` is both {allow.access} and deny; deny wins"))
    for parent, child in resolved.overridden:
        if parent.access in ("deny", "none") and child.access in ("read", "write"):
            out.append(finding("KO024", p, child.line, name, child.path,
                               f"profile `{child.profile}` sets `{_show(child.path)}` = {child.access}, removing "
                               f"`{parent.profile}`'s deny"))
    if resolved.base == ":workspace":
        out.append(finding("KO050", p, None, name, ":workspace",
                           f"profile `{name}` extends :workspace (also writes /tmp and $TMPDIR)"))
    if resolved.network.get("enabled") is True:
        domains = resolved.network.get("domains")
        names = list(domains) if isinstance(domains, (list, dict)) else []
        if any(isinstance(item, str) and (item in ("*", "**") or item.startswith("**.")) for item in names):
            out.append(finding("KO051", p, cc.find_line(cfg.text, "domains"), name, "network.domains",
                               "network is enabled for a wildcard domain"))
    return out


def _show(path: str) -> str:
    return path.replace(cc.FIXTURE_ROOT, cc.FIXTURE_PLACEHOLDER)


def _dedupe(findings: list[dict]) -> list[dict]:
    seen, out = set(), []
    for item in findings:
        key = (item["id"], item["profile"], item["path"], item["message"])
        if key not in seen:
            seen.add(key)
            out.append(item)
    return out


def _sorted(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda item: (SEVERITIES.index(item["severity"]), item["line"] or 0, item["id"]))


def exit_code(findings: list[dict]) -> int:
    severities = {item["severity"] for item in findings}
    return 2 if "error" in severities else 1 if "high" in severities else 0


def render(findings: list[dict]) -> str:
    if not findings:
        return "no findings\n"
    lines = []
    for item in findings:
        where = f"{item['file']}:{item['line'] if item['line'] else '?'}"
        prefix = f"[{item['profile']}] " if item["profile"] else ""
        lines.append(f"{item['id']} {item['severity']} {where} {prefix}{item['message']}")
        lines.append(f"    why: {item['why']}")
        lines.append(f"    fix: {item['fix']}")
        if item.get("codex_said"):
            lines.append(f"    codex said: {item['codex_said']}")
    counts = {name: sum(item["severity"] == name for item in findings) for name in SEVERITIES}
    lines.append("summary: " + ", ".join(f"{name} {count}" for name, count in counts.items()))
    return "\n".join(lines) + "\n"


# ---- --codex-check: a dead-provider session start in a fake CODEX_HOME ----

DEAD_PROVIDER = ["-c", 'model_providers.ko={name="ko",base_url="http://127.0.0.1:9/v1",wire_api="responses"}',
                 "-c", "model_provider=ko", "-c", "model=none"]
NEVER_COPY = frozenset({"mcp_servers", "hooks", "notify", "model_providers", "model_provider", "profiles", "profile",
                        "shell_environment_policy", "projects", "otel", "chatgpt_base_url", "model_instructions_file",
                        "experimental_instructions_file", "file_opener", "log_dir", "sqlite_home", "agents",
                        "skills", "tools", "features"})
RISKY = re.compile(r"url|provider|command|notify|hook|mcp|exec|shell|auth|login|token|key|secret|path|file|dir")
CHECK_NOTE = ("--codex-check is a session start against a dead provider at 127.0.0.1:9 in a fake CODEX_HOME: no "
              "auth and no model turn are possible; only top-level scalars/arrays, [permissions.*] and "
              "[sandbox_workspace_write] are copied.")


def sanitized(cfg: CodexConfig) -> dict:
    """Only top-level scalars and arrays, [permissions.*] and [sandbox_workspace_write]."""
    out: dict = {}
    for key, value in cfg.data.items():
        if key in NEVER_COPY:
            continue
        if key == "permissions" and isinstance(value, dict):
            out[key] = value
        elif key == "sandbox_workspace_write" and isinstance(value, dict):
            out[key] = value
        elif isinstance(value, (str, bool, int, list)) and not RISKY.search(key):
            out[key] = value
        elif key in cc.KNOWN_IGNORED_TOP:
            out[key] = value
    return out


def check_commands(cli: str) -> list[list[str]]:
    base = ["exec", "--skip-git-repo-check", "--ephemeral", *DEAD_PROVIDER, "keepout-config-check"]
    return [[cli, base[0], "--strict-config", *base[1:]], [cli, *base]]


Run = Callable[..., subprocess.CompletedProcess]


def codex_check(cfg: CodexConfig, findings: list[dict], cli: str | None = None, run: Run = subprocess.run,
                serialize: Callable[[dict], str] | None = None) -> dict:
    """Attach what Codex itself says to the matching findings. Returns a receipt."""
    from .codex import find_codex
    cli = cli or find_codex()
    copy = sanitized(cfg)
    try:
        text = (serialize or cc.dumps)(copy)
    except TypeError:  # an unsupported value type (float, date, mixed array): keep the permission settings alone
        copy = {key: copy[key] for key in ("default_permissions", "permissions", "sandbox_permissions")
                if key in copy}
        text = cc.dumps(copy)
    said: list[str] = []
    with tempfile.TemporaryDirectory(prefix="keepout-check-", dir=tempfile.gettempdir()) as temp:
        fake = Path(temp).resolve()
        (fake / "tmp").mkdir()
        (fake / "work").mkdir()
        (fake / "config.toml").write_text(text, encoding="utf-8")
        env = {"PATH": "/usr/bin:/bin", "HOME": str(fake), "CODEX_HOME": str(fake), "TMPDIR": str(fake / "tmp"),
               "LANG": os.environ.get("LANG", "en_US.UTF-8")}
        for command in check_commands(cli):
            try:
                result = run(command, cwd=str(fake / "work"), env=env, stdin=subprocess.DEVNULL,
                             capture_output=True, text=True, timeout=8)
                output = (result.stdout or "") + (result.stderr or "")
            except subprocess.TimeoutExpired as exc:
                output = "".join(part.decode() if isinstance(part, bytes) else (part or "")
                                 for part in (exc.stdout, exc.stderr))
            said.extend(line.strip().replace(str(fake), "<temp>") for line in output.splitlines()
                        if _interesting(line))
    said = list(dict.fromkeys(said))
    _attach(said, findings, cfg.path)
    return {"note": CHECK_NOTE, "copied_keys": sorted(copy), "codex_said": said,
            "commands": [" ".join(command[1:]) for command in check_commands("codex")]}


def _interesting(line: str) -> bool:
    return bool(re.search(r"unknown configuration field|is ignored|is not recognized|Error:|error:", line))


def _attach(said: list[str], findings: list[dict], cfg_path: str) -> None:
    for line in said:
        names = re.findall(r"`([^`]+)`", line)
        match = next((item for item in findings for name in names
                      if item["path"] in (name, name.replace(cc.FIXTURE_ROOT, cc.FIXTURE_PLACEHOLDER))), None)
        if match is not None:
            match["codex_said"] = "; ".join(filter(None, [match.get("codex_said"), line]))
        else:
            findings.append(finding("KO090", cfg_path, message=line[:300]))
