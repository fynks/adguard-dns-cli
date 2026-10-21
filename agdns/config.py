"""Local configuration storage for the AdGuard DNS CLI.

The API key is stored in a JSON file inside the user's config directory with
restrictive permissions (0600 for the file, 0700 for the directory).
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any

APP_NAME = "agdns-cli"
ENV_API_KEY = "AGDNS_API_KEY"
ENV_CONFIG_DIR = "AGDNS_CONFIG_DIR"

DEFAULT_API_URL = "https://api.adguard-dns.io"


def config_dir() -> Path:
    """Return the directory where the configuration is stored."""
    env_dir = os.environ.get(ENV_CONFIG_DIR)
    if env_dir:
        return Path(env_dir).expanduser()

    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        return Path(xdg).expanduser() / APP_NAME

    return Path.home() / ".config" / APP_NAME


def config_file() -> Path:
    return config_dir() / "config.json"


def _read() -> dict[str, Any]:
    path = config_file()
    if not path.exists():
        return {}
    try:
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _write(data: dict[str, Any]) -> None:
    directory = config_dir()
    directory.mkdir(parents=True, exist_ok=True)
    try:
        directory.chmod(stat.S_IRWXU)
    except OSError:
        pass

    path = config_file()
    tmp = path.with_suffix(".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, sort_keys=True)
        f.write("\n")
    os.chmod(tmp, stat.S_IRUSR | stat.S_IWUSR)
    tmp.replace(path)


def get_api_key() -> str | None:
    """Return the API key from the environment or the local config file."""
    env_key = os.environ.get(ENV_API_KEY)
    if env_key:
        return env_key.strip()
    key = _read().get("api_key")
    if isinstance(key, str) and key.strip():
        return key.strip()
    return None


def set_api_key(api_key: str) -> None:
    data = _read()
    data["api_key"] = api_key.strip()
    _write(data)


def clear_api_key() -> None:
    data = _read()
    data.pop("api_key", None)
    _write(data)


def get_api_url() -> str:
    url = _read().get("api_url")
    if isinstance(url, str) and url.strip():
        return url.strip().rstrip("/")
    return DEFAULT_API_URL


def set_api_url(url: str) -> None:
    data = _read()
    data["api_url"] = url.strip().rstrip("/")
    _write(data)
