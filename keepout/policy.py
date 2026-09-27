"""Small, deliberately restricted policy format for disposable probe paths."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path, PurePosixPath
import tomllib


@dataclass(frozen=True)
class Policy:
    protected_paths: tuple[str, ...]
    writable_paths: tuple[str, ...]
    network: bool
    inherit_fake_token: bool
    external_routes: bool = False


def _paths(value: object, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{field} must be a nonempty list of relative directories")
    paths = []
    for item in value:
        if not isinstance(item, str) or not item or "\\" in item:
            raise ValueError(f"{field} contains an invalid path")
        path = PurePosixPath(item)
        if path.is_absolute() or any(part in (".", "..") for part in item.split("/")) or str(path) != item:
            raise ValueError(f"{field} paths must be normalized and relative")
        if path.parts[0] not in ("home", "work", "protected", "outside"):
            raise ValueError(f"{field} paths must stay in the disposable root")
        paths.append(item)
    if len(paths) != len(set(paths)):
        raise ValueError(f"{field} contains duplicates")
    return tuple(paths)


def load_policy(path: str | Path) -> Policy:
    file = Path(path)
    if file.suffix == ".toml":
        with file.open("rb") as stream:
            data = tomllib.load(stream)
    elif file.suffix == ".json":
        with file.open(encoding="utf-8") as stream:
            data = json.load(stream)
    else:
        raise ValueError("policy must be a .toml or .json file")
    if not isinstance(data, dict):
        raise ValueError("policy must be an object")
    expected = {"protected_paths", "writable_paths", "network", "inherit_fake_token"}
    if not expected.issubset(data) or set(data) - (expected | {"external_routes"}):
        raise ValueError(f"policy fields must be: {', '.join(sorted(expected))}; optional: external_routes")
    protected = _paths(data["protected_paths"], "protected_paths")
    writable = _paths(data["writable_paths"], "writable_paths")
    if "work" not in writable:
        raise ValueError("writable_paths must include work for the symlink probe")
    for left in protected:
        for right in writable:
            if left == right or left.startswith(right + "/") or right.startswith(left + "/"):
                raise ValueError("protected and writable paths must not overlap")
    if type(data["network"]) is not bool or type(data["inherit_fake_token"]) is not bool:
        raise ValueError("network and inherit_fake_token must be booleans")
    external = data.get("external_routes", False)
    if type(external) is not bool or (external and not data["network"]):
        raise ValueError("external_routes must be a boolean and requires network=true")
    return Policy(protected, writable, data["network"], data["inherit_fake_token"], external)
