import os
from typing import List, Dict


class ConfigError(Exception):
    pass


def get_env(name: str, required: bool = True, default: str | None = None) -> str:
    value = os.getenv(name, default)
    if required and not value:
        raise ConfigError(f"Missing required environment variable: {name}")
    return value


def parse_csv(value: str) -> List[str]:
    """
    Parse a comma-separated env var into a clean list.
    """
    return [v.strip() for v in value.split(",") if v.strip()]


def get_target_groups() -> Dict[str, List[str]]:
    """
    Load targets grouped by logical purpose.

    Example:
    TARGETS_TEST="8.8.8.8,1.1.1.1"
    TARGETS_OWNED="203.0.113.10,203.0.113.11"
    """
    groups: Dict[str, List[str]] = {}

    for env_name in os.environ:
        if not env_name.startswith("TARGETS_"):
            continue

        group_name = env_name.replace("TARGETS_", "").lower()
        targets = parse_csv(os.environ[env_name])

        if targets:
            groups[group_name] = targets

    if not groups:
        raise ConfigError("No TARGETS_* environment variables defined")

    return groups


class Config:
    # Shodan
    SHODAN_API_KEY: str = get_env("SHODAN_API_KEY")

    # Target groups
    TARGET_GROUPS: Dict[str, List[str]] = get_target_groups()

    # Flattened list used by the collector (for now)
    TARGETS: List[str] = sorted(
        {ip for group in TARGET_GROUPS.values() for ip in group}
    )

    # Timing / rate limiting
    INTERVAL_SECONDS: int = int(
        get_env("INTERVAL_SECONDS", required=False, default="21600")
    )
    REQUEST_DELAY: float = float(
        get_env("REQUEST_DELAY", required=False, default="1.0")
    )

    # Database
    DB_HOST: str = get_env("DB_HOST")
    DB_NAME: str = get_env("DB_NAME")
    DB_USER: str = get_env("DB_USER")
    DB_PASS: str = get_env("DB_PASS")
