import os
from typing import List


class ConfigError(Exception):
    pass


def get_env(name: str, required: bool = True, default: str | None = None) -> str:
    value = os.getenv(name, default)
    if required and not value:
        raise ConfigError(f"Missing required environment variable: {name}")
    return value


def get_targets() -> List[str]:
    raw = get_env("TARGETS")
    targets = [t.strip() for t in raw.split(",") if t.strip()]
    if not targets:
        raise ConfigError("TARGETS is empty after parsing")
    return targets


class Config:
    # Shodan
    SHODAN_API_KEY: str = get_env("SHODAN_API_KEY")

    # Targets
    TARGETS: List[str] = get_targets()

    # Timing / rate limiting
    INTERVAL_SECONDS: int = int(get_env("INTERVAL_SECONDS", required=False, default="21600"))
    REQUEST_DELAY: float = float(get_env("REQUEST_DELAY", required=False, default="1.0"))

    # Database
    DB_HOST: str = get_env("DB_HOST")
    DB_NAME: str = get_env("DB_NAME")
    DB_USER: str = get_env("DB_USER")
    DB_PASS: str = get_env("DB_PASS")

