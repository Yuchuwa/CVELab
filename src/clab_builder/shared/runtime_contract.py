"""Shared runtime/flag/validation helpers for atoms and scenarios."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Iterable


DEFAULT_PROXY_ENV_KEYS = [
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
]

DEFAULT_FLAG_ENV_VAR = "FLAG"
DEFAULT_FLAG_PRIMARY_PATH = "/flag.txt"
DEFAULT_FLAG_FALLBACK_PATHS = ["/flag", "/tmp/flag.txt", "/root/flag.txt"]


def default_flag_paths(primary_path: str = DEFAULT_FLAG_PRIMARY_PATH) -> list[str]:
    seen: list[str] = []
    for path in [primary_path, *DEFAULT_FLAG_FALLBACK_PATHS]:
        if path not in seen:
            seen.append(path)
    return seen


def build_flag_injection_command(
    flag: str,
    primary_path: str = DEFAULT_FLAG_PRIMARY_PATH,
    fallback_paths: Iterable[str] | None = None,
) -> str:
    """Build a target-side shell command that writes the flag to all paths."""
    flag_esc = flag.replace("'", "'\\''")
    all_paths = default_flag_paths(primary_path)
    if fallback_paths:
        for path in fallback_paths:
            if path not in all_paths:
                all_paths.append(path)

    commands: list[str] = []
    first_path = all_paths[0]
    first_dir = str(Path(first_path).parent)
    if first_dir not in ("", "."):
        commands.append(f"mkdir -p {first_dir}")
    commands.append(f"printf '%s' '{flag_esc}' > {first_path}")

    for path in all_paths[1:]:
        parent = str(Path(path).parent)
        if parent not in ("", "."):
            commands.append(f"mkdir -p {parent}")
        commands.append(f"cp {first_path} {path}")

    # Keep world-readable copies except the root-only path.
    for path in all_paths:
        if path.startswith("/root/"):
            commands.append(f"chmod 600 {path}")
        else:
            commands.append(f"chmod 644 {path}")

    return " && ".join(commands)


def render_command_template(command: str, values: dict[str, object]) -> str:
    """Render '{{ var }}' placeholders in atom replay/verify commands."""
    text = command or ""
    for key, value in values.items():
        text = re.sub(r"{{\s*" + re.escape(key) + r"\s*}}", str(value), text)
    return text


def contains_unresolved_template(command: str) -> bool:
    return "{{" in (command or "") and "}}" in (command or "")


def sha256_file(path: str | Path) -> str:
    data = Path(path).read_bytes()
    return hashlib.sha256(data).hexdigest()


def dump_json(data: object) -> str:
    return json.dumps(data, indent=2, ensure_ascii=False)
