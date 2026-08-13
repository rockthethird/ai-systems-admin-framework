"""Validate the executable collector-policy contract without external dependencies."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

POLICY_VERSION = "ai-auditor-collectors/v1"
MAX_COLLECTORS = 1000
MAX_CANDIDATES = 20
MAX_PARAMETER_VALUES = 100
MAX_TEXT_LENGTH = 1000
LIMIT_BOUNDS = {
    "command_timeout_seconds": (1, 60),
    "max_items": (1, 10000),
    "max_stream_bytes": (1024, 4194304),
    "max_cpu_seconds": (1, 30),
    "max_open_files": (16, 1024),
    "max_file_bytes": (1024, 4194304),
}
PRIMITIVE_PARAMETERS = {
    "passwd-entries": frozenset(),
    "host-platform": frozenset(),
    "os-release": frozenset(),
    "ssh-effective-settings": frozenset({"users", "settings", "executable_paths"}),
    "account-path-metadata": frozenset({"users", "relative_paths"}),
    "path-metadata": frozenset({"paths"}),
}

_IDENTIFIER = re.compile(r"^[a-z][a-z0-9-]*$")
_COMMON_FIELDS = {"id", "type", "optional"}
_COMMAND_FIELDS = _COMMON_FIELDS | {"candidates", "parser", "max_items"}
_BUILTIN_FIELDS = _COMMON_FIELDS | {"primitive", "parameters"}


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def _string_list(value: Any, label: str) -> list[str]:
    _require(isinstance(value, list) and bool(value), f"{label} must be a non-empty list")
    _require(len(value) <= MAX_PARAMETER_VALUES, f"{label} contains too many values")
    _require(all(isinstance(item, str) and item and "\x00" not in item
                 and len(item) <= MAX_TEXT_LENGTH for item in value),
             f"{label} contains an invalid value")
    return value


def _validate_parameters(identifier: str, primitive: str, parameters: Any) -> None:
    _require(isinstance(parameters, dict), f"collector {identifier} parameters are invalid")
    expected = PRIMITIVE_PARAMETERS[primitive]
    _require(set(parameters) == expected,
             f"collector {identifier} parameters do not match {primitive}")

    for name, value in parameters.items():
        values = _string_list(value, f"collector {identifier} {name}")
        if name in {"paths", "executable_paths"}:
            _require(all(os.path.isabs(item) for item in values),
                     f"collector {identifier} {name} must be absolute")
        elif name == "relative_paths":
            _require(all(not Path(item).is_absolute() and ".." not in Path(item).parts
                         for item in values),
                     f"collector {identifier} relative path escapes its account home")


def _validate_command(identifier: str, collector: dict[str, Any], defaults: dict[str, int]) -> None:
    _require(set(collector) <= _COMMAND_FIELDS,
             f"command collector {identifier} contains unknown fields")
    _require(collector.get("parser") == "lines",
             f"command collector {identifier} parser is invalid")
    candidates = collector.get("candidates")
    _require(isinstance(candidates, list) and 1 <= len(candidates) <= MAX_CANDIDATES,
             f"command collector {identifier} candidates are invalid")
    max_items = collector.get("max_items", defaults["max_items"])
    _require(isinstance(max_items, int) and not isinstance(max_items, bool)
             and 1 <= max_items <= 10000,
             f"command collector {identifier} has an invalid item limit")

    for candidate in candidates:
        _require(isinstance(candidate, dict) and set(candidate) == {"path", "args"},
                 f"command collector {identifier} candidate is invalid")
        path = candidate["path"]
        arguments = candidate["args"]
        _require(isinstance(path, str) and os.path.isabs(path) and "\x00" not in path
                 and len(path) <= MAX_TEXT_LENGTH,
                 f"command collector {identifier} path is unsafe")
        _require(isinstance(arguments, list) and len(arguments) <= MAX_CANDIDATES
                 and all(isinstance(argument, str) and "\x00" not in argument
                         and len(argument) <= MAX_TEXT_LENGTH for argument in arguments),
                 f"command collector {identifier} arguments are unsafe")


def validate_collector_policy(policy: Any) -> None:
    """Accept a complete collector policy or raise ``ValueError``."""
    _require(isinstance(policy, dict)
             and set(policy) == {"version", "defaults", "collectors"},
             "collector policy is invalid")
    _require(policy["version"] == POLICY_VERSION, "unsupported collector policy")

    defaults = policy["defaults"]
    _require(isinstance(defaults, dict) and set(defaults) == set(LIMIT_BOUNDS),
             "collector limits are invalid")
    for name, (minimum, maximum) in LIMIT_BOUNDS.items():
        value = defaults[name]
        _require(isinstance(value, int) and not isinstance(value, bool)
                 and minimum <= value <= maximum,
                 "collector limits are invalid")

    collectors = policy["collectors"]
    _require(isinstance(collectors, list) and 1 <= len(collectors) <= MAX_COLLECTORS,
             "collector catalog is invalid")
    seen: set[str] = set()
    for collector in collectors:
        _require(isinstance(collector, dict), "collector entry is invalid")
        identifier = collector.get("id")
        _require(isinstance(identifier, str) and bool(_IDENTIFIER.fullmatch(identifier)),
                 "collector ID is invalid")
        _require(identifier not in seen, "collector IDs must be unique")
        seen.add(identifier)
        _require(isinstance(collector.get("optional", False), bool),
                 f"collector {identifier} optional flag is invalid")

        collector_type = collector.get("type")
        if collector_type == "command":
            _validate_command(identifier, collector, defaults)
        elif collector_type == "builtin":
            _require(set(collector) <= _BUILTIN_FIELDS,
                     f"builtin collector {identifier} contains unknown fields")
            primitive = collector.get("primitive")
            _require(isinstance(primitive, str) and primitive in PRIMITIVE_PARAMETERS,
                     f"collector {identifier} uses an unknown primitive")
            _validate_parameters(identifier, primitive, collector.get("parameters", {}))
        else:
            raise ValueError(f"collector {identifier} has an unknown type")
