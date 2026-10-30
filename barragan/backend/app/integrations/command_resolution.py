# Copyright (c) 2026, Oracle and/or its affiliates.
from __future__ import annotations

import os
import shutil
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping, Sequence


@dataclass(frozen=True)
class CommandResolution:
    binary_name: str
    command: str | None
    source: str | None
    override_variables: tuple[str, ...]
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.command is not None and self.error is None


def resolve_executable(
    binary_name: str,
    *,
    override_variables: Sequence[str],
    fallback_paths: Sequence[str | Path] = (),
    env: Mapping[str, str] | None = None,
    display_name: str | None = None,
) -> CommandResolution:
    lookup_env = env if env is not None else os.environ
    overrides = tuple(override_variables)
    label = display_name or binary_name

    for variable in overrides:
        value = lookup_env.get(variable, "").strip()
        if not value:
            continue
        resolved_override = _resolve_candidate(value, lookup_env)
        if resolved_override is not None:
            return CommandResolution(
                binary_name=binary_name,
                command=resolved_override,
                source=f"env:{variable}",
                override_variables=overrides,
            )
        return CommandResolution(
            binary_name=binary_name,
            command=None,
            source=f"env:{variable}",
            override_variables=overrides,
            error=(
                f"Could not resolve {label} executable from {variable}={value!r}; "
                f"set {variable} to an executable path."
            ),
        )

    path_match = shutil.which(binary_name, path=lookup_env.get("PATH"))
    if path_match is not None:
        return CommandResolution(
            binary_name=binary_name,
            command=path_match,
            source="path",
            override_variables=overrides,
        )

    for fallback in fallback_paths:
        fallback_path = str(fallback)
        if _is_executable_file(fallback_path):
            return CommandResolution(
                binary_name=binary_name,
                command=fallback_path,
                source="fallback",
                override_variables=overrides,
            )

    override_help = _format_override_help(overrides)
    return CommandResolution(
        binary_name=binary_name,
        command=None,
        source=None,
        override_variables=overrides,
        error=f"Could not resolve {label} executable; set {override_help} to an executable path.",
    )


def _resolve_candidate(candidate: str, env: Mapping[str, str]) -> str | None:
    if os.sep in candidate or (os.altsep is not None and os.altsep in candidate):
        return candidate if _is_executable_file(candidate) else None
    return shutil.which(candidate, path=env.get("PATH"))


def _is_executable_file(path: str) -> bool:
    return os.path.isfile(path) and os.access(path, os.X_OK)


def _format_override_help(overrides: tuple[str, ...]) -> str:
    if len(overrides) == 1:
        return overrides[0]
    return " or ".join(overrides)
