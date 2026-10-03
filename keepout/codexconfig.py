"""Read an existing Codex config.toml and resolve its permission profiles.

Parsing and resolution only: nothing here executes Codex, stats a configured path or reads any file other than the
one config file it is given. Normalization and remapping are pure string work.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import posixpath
import re
import tomllib


MEASURED = "codex-cli 0.156.1 macOS 2026-10-03"

# Codex 0.156.1 docs + measured 2026-10-03: the keys a [permissions.<name>] table understands.
PROFILE_KEYS = frozenset({"extends", "description", "filesystem", "network", "workspace_roots"})
# Codex 0.156.1 docs + measured 2026-10-03: `mode` is NOT one of them (silently ignored).
NETWORK_KEYS = frozenset({"enabled", "domains", "allow_local_binding", "unix_sockets"})
# Codex 0.156.1 docs + binary strings, measured 2026-10-03: recognized special path tokens.
TOKENS = frozenset({":root", ":minimal", ":workspace_roots", ":tmpdir", ":slash_tmp"})
# Codex 0.156.1 docs: read/write/deny. Measured 2026-10-03: "none" is accepted and denies reads (undocumented).
VALUES = frozenset({"read", "write", "deny"})
UNDOCUMENTED_VALUES = frozenset({"none"})
# Codex 0.156.1 docs + measured 2026-10-03 (":readonly" is refused).
BUILTINS = frozenset({":read-only", ":workspace", ":danger-full-access"})
# Measured 2026-10-03: accepted by `codex sandbox` without a word, warned about by `codex exec`.
KNOWN_IGNORED_TOP = frozenset({"sandbox_permissions"})
# Curated from the 0.156.1 config-reference page. Used only for info-level findings (KO003).
KNOWN_TOP = frozenset({
    "model", "model_provider", "model_providers", "model_reasoning_effort", "model_reasoning_summary",
    "model_verbosity", "model_context_window", "model_auto_compact_token_limit", "model_supports_reasoning_summaries",
    "review_model", "approval_policy", "sandbox_mode", "sandbox_workspace_write", "default_permissions",
    "permissions", "profile", "profiles", "mcp_servers", "hooks", "notify", "shell_environment_policy", "history",
    "tui", "file_opener", "hide_agent_reasoning", "show_raw_agent_reasoning", "project_doc_max_bytes",
    "project_doc_fallback_filenames", "projects", "features", "tools", "otel", "disable_response_storage",
    "preferred_auth_method", "forced_login_method", "forced_chatgpt_workspace_id", "cli_auth_credentials_store",
    "chatgpt_base_url", "instructions", "developer_instructions", "model_instructions_file",
    "experimental_instructions_file", "web_search", "windows_wsl_setup_acknowledged", "personality", "analytics",
    "feedback", "notice", "check_for_update_on_startup", "log_dir", "sqlite_home", "agents", "skills",
})
# macOS firmlinks Codex 0.156.1 canonicalizes (measured 2026-10-03).
MAC_ALIASES = {"/tmp": "/private/tmp", "/var": "/private/var", "/etc": "/private/etc"}
# Real folders Keepout never reads a config from unless the owner says the file is theirs.
GUARDED_HOME_DIRS = (".codex", ".claude", ".ssh", ".config")
# A fixture placeholder: tests and fixtures write `{R}` for a disposable root.
FIXTURE_PLACEHOLDER = "{R}"
FIXTURE_ROOT = "/keepout-fixture-root"


class ConfigError(ValueError):
    def __init__(self, message: str, line: int | None = None):
        super().__init__(message)
        self.line = line


class RefusedPath(PermissionError):
    pass


@dataclass(frozen=True)
class Entry:
    profile: str
    scope: str  # abs | home | token | workspace_roots | relative
    path: str  # the string exactly as written (a :workspace_roots child is its relative subpath)
    access: object  # the raw value; "table" for a subtable
    line: int | None = None

    @property
    def key(self) -> tuple[str, str]:
        return (self.scope, normalize(self.path) if self.scope in ("abs", "home", "workspace_roots") else self.path)

    @property
    def label(self) -> str:
        return f":workspace_roots/{self.path}" if self.scope == "workspace_roots" else self.path


@dataclass
class Profile:
    name: str
    extends: str | None
    keys: list[str]
    filesystem: list[Entry]
    network: dict
    workspace_roots: list[str]
    line: int | None = None


@dataclass
class CodexConfig:
    path: str
    text: str
    data: dict
    profiles: dict[str, Profile]
    sha256: str
    placeholder: bool = False

    @property
    def default_permissions(self) -> object:
        return self.data.get("default_permissions")


@dataclass
class ResolvedProfile:
    name: str
    chain: list[str]  # child first, ending in a built-in when there is one
    base: str | None
    filesystem: list[Entry]
    network: dict
    workspace_roots: list[str]
    overridden: list[tuple[Entry, Entry]] = field(default_factory=list)

    def access(self, path: str) -> list[str]:
        return [str(entry.access) for entry in self.filesystem if entry.path == path]


def scope_of(path: str) -> str:
    if path.startswith(":"):
        return "token"
    if path == "~" or path.startswith("~/"):
        return "home"
    if path.startswith("/"):
        return "abs"
    return "relative"


def normalize(path: str) -> str:
    """Pure string canonicalization: alias prefix, `//`, `.`/`..` lexically, trailing `/`. Never stats."""
    if path.startswith("~"):
        rest = normalize("/" + path[2:]) if path.startswith("~/") else ""
        return "~" + (rest if rest != "/" else "")
    if not path.startswith("/"):
        cleaned = posixpath.normpath(re.sub(r"/+", "/", path)) if path else path
        return cleaned
    cleaned = posixpath.normpath(re.sub(r"/+", "/", path))
    if cleaned.startswith("//"):
        cleaned = "/" + cleaned.lstrip("/")
    for alias, real in MAC_ALIASES.items():
        if cleaned == alias or cleaned.startswith(alias + "/"):
            cleaned = real + cleaned[len(alias):]
            break
    return cleaned


def covers(outer: str, inner: str) -> bool:
    """True when normalized `inner` is `outer` or below it."""
    return inner == outer or inner.startswith(outer.rstrip("/") + "/")


def is_glob(path: str) -> bool:
    return any(char in path for char in "*?[]{}")


def guarded(path: Path) -> str | None:
    home = Path.home()
    real = Path(os.path.realpath(path))
    for name in GUARDED_HOME_DIRS:
        for base in {home / name, Path(os.path.realpath(home / name))}:
            if real == base or real.is_relative_to(base) or path.absolute().is_relative_to(base):
                return str(base)
    return None


def load_codex_config(path: str | Path, i_own_this_file: bool = False) -> CodexConfig:
    """Read exactly one file. Refuse a real ~/.codex, ~/.claude, ~/.ssh or ~/.config file unless the owner says so."""
    file = Path(path)
    refused = guarded(file)
    if refused and not i_own_this_file:
        raise RefusedPath(f"refusing to read a file under {refused}; pass --i-own-this-file if it is yours "
                          "(Keepout then reads only that one file)")
    raw = file.read_bytes()
    text = raw.decode("utf-8")
    placeholder = FIXTURE_PLACEHOLDER in text
    parsed_text = text.replace(FIXTURE_PLACEHOLDER, FIXTURE_ROOT) if placeholder else text
    try:
        data = tomllib.loads(parsed_text)
    except tomllib.TOMLDecodeError as exc:
        match = re.search(r"line (\d+)", str(exc))
        raise ConfigError(str(exc), int(match.group(1)) if match else None) from None
    profiles: dict[str, Profile] = {}
    permissions = data.get("permissions")
    if isinstance(permissions, dict):
        for name, table in permissions.items():
            if isinstance(table, dict):
                profiles[name] = _profile(name, table, text)
    return CodexConfig(str(file), text, data, profiles, hashlib.sha256(raw).hexdigest(), placeholder)


def find_line(text: str, needle: str, start: int = 0) -> int | None:
    """Best-effort 1-based line of a quoted key, bare key or table header at or after line index `start`."""
    lines = text.splitlines()
    if needle.startswith("["):
        patterns = [re.compile(r"^\s*" + re.escape(needle))]
    else:
        quoted = json.dumps(needle).replace(FIXTURE_ROOT, FIXTURE_PLACEHOLDER)
        patterns = [re.compile(re.escape(quoted) + r"\s*="), re.compile(r"'" + re.escape(needle) + r"'\s*=")]
        if re.fullmatch(r"[A-Za-z0-9_-]+", needle):
            patterns.append(re.compile(r"(^|[\s{,.])" + re.escape(needle) + r"\s*="))
    for index in range(start, len(lines)):
        if any(pattern.search(lines[index]) for pattern in patterns):
            return index + 1
    return None


def _profile_start(text: str, name: str) -> int:
    line = find_line(text, f"[permissions.{name}") or find_line(text, f'[permissions."{name}"')
    return (line - 1) if line else 0


def _profile(name: str, table: dict, text: str) -> Profile:
    start = _profile_start(text, name)
    entries: list[Entry] = []
    filesystem = table.get("filesystem")
    if isinstance(filesystem, dict):
        for key, value in filesystem.items():
            line = find_line(text, key.replace(FIXTURE_ROOT, FIXTURE_PLACEHOLDER), start) or \
                find_line(text, key, start)
            if isinstance(value, dict):
                entries.append(Entry(name, scope_of(key), key, "table", line))
                for sub, access in value.items():
                    sub_line = find_line(text, sub, start)
                    if key == ":workspace_roots":
                        entries.append(Entry(name, "workspace_roots", sub, access, sub_line))
                    else:
                        joined = key.rstrip("/") + "/" + sub
                        entries.append(Entry(name, scope_of(joined), joined, access, sub_line))
            else:
                entries.append(Entry(name, scope_of(key), key, value, line))
    network = table.get("network") if isinstance(table.get("network"), dict) else {}
    roots = table.get("workspace_roots")
    roots = [item for item in roots if isinstance(item, str)] if isinstance(roots, list) else []
    extends = table.get("extends") if isinstance(table.get("extends"), str) else None
    return Profile(name, extends, list(table), entries, dict(network), roots, start + 1 if start else None)


def chain(cfg: CodexConfig, name: str) -> list[str]:
    """Child first. Raises ConfigError on an undefined profile, unsupported built-in or cycle."""
    seen: list[str] = []
    current: str | None = name
    while current is not None:
        if current in BUILTINS:
            seen.append(current)
            return seen
        if current.startswith(":"):
            raise ConfigError(f"cannot extend unsupported built-in profile `{current}`")
        if current in seen:
            raise ConfigError("extends cycle: " + " -> ".join(seen + [current]))
        profile = cfg.profiles.get(current)
        if profile is None:
            raise ConfigError(f"refers to undefined profile `{current}`")
        seen.append(current)
        current = profile.extends
    return seen


def resolve(cfg: CodexConfig, name: str) -> ResolvedProfile:
    names = chain(cfg, name)
    base = names[-1] if names[-1] in BUILTINS else None
    merged: dict[tuple[str, str], list[Entry]] = {}
    network: dict = {}
    roots: list[str] = []
    overridden: list[tuple[Entry, Entry]] = []
    for profile_name in reversed([item for item in names if item not in BUILTINS]):
        profile = cfg.profiles[profile_name]
        own: dict[tuple[str, str], list[Entry]] = {}
        for entry in profile.filesystem:
            if entry.access == "table":
                continue
            own.setdefault(entry.key, []).append(entry)
        for key, entries in own.items():
            for parent in merged.get(key, []):
                for child in entries:
                    overridden.append((parent, child))
            merged[key] = entries
        network.update(profile.network)
        if profile.workspace_roots:
            roots = list(profile.workspace_roots)
    filesystem = [entry for entries in merged.values() for entry in entries]
    return ResolvedProfile(name, names, base, filesystem, network, roots, overridden)


# ---- a tiny TOML writer: strings, bools, ints, arrays of strings and nested tables; keys always quoted ----

def _value(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return "[" + ", ".join(json.dumps(item) for item in value) + "]"
    raise TypeError(f"unsupported TOML value: {type(value).__name__}")


def dumps(data: dict) -> str:
    lines: list[str] = []

    def table(prefix: list[str], body: dict) -> None:
        scalars = [(key, value) for key, value in body.items() if not isinstance(value, dict)]
        tables = [(key, value) for key, value in body.items() if isinstance(value, dict)]
        if prefix and (scalars or not tables):
            lines.append("[" + ".".join(json.dumps(part) for part in prefix) + "]")
        for key, value in scalars:
            lines.append(f"{json.dumps(key)} = {_value(value)}")
        if prefix and scalars:
            lines.append("")
        for key, value in tables:
            table(prefix + [key], value)

    table([], data)
    return "\n".join(lines).rstrip() + "\n"
