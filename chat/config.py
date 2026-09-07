"""Load and validate the editable server configuration."""

import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = PROJECT_ROOT / "config.json"


def _require_mapping(config, name):
    value = config.get(name)
    if not isinstance(value, dict):
        raise ValueError(f"Configuration section '{name}' must be an object.")
    return value


def _require_number(section, key, minimum=None, maximum=None):
    value = section.get(key)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"Configuration value '{key}' must be a number.")
    if minimum is not None and value < minimum:
        raise ValueError(f"Configuration value '{key}' must be at least {minimum}.")
    if maximum is not None and value > maximum:
        raise ValueError(f"Configuration value '{key}' must be at most {maximum}.")
    return value


def _require_integer(section, key, minimum=None, maximum=None):
    value = section.get(key)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"Configuration value '{key}' must be an integer.")
    _require_number(section, key, minimum, maximum)
    return value


def _require_text(section, key):
    value = section.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Configuration value '{key}' must be non-empty text.")
    return value


def validate_config(config):
    """Validate editable values and return the same configuration object."""
    if not isinstance(config, dict):
        raise ValueError("The configuration root must be an object.")

    network = _require_mapping(config, "network")
    _require_text(network, "host")
    _require_integer(network, "chat_port", 0, 65535)
    _require_integer(network, "api_port", 0, 65535)
    _require_number(network, "handshake_timeout_seconds", 0.1)
    _require_number(network, "client_thread_join_timeout_seconds", 0.1)
    _require_integer(network, "generated_room_token_bytes", 1)
    _require_text(network, "api_server_version")

    limits = _require_mapping(config, "limits")
    for key in ("message_bytes", "room_bytes", "auth_bytes"):
        _require_integer(limits, key, 1)
    _require_integer(limits, "room_min_characters", 1, limits["room_bytes"])
    username_min = _require_integer(limits, "username_min_characters", 1)
    username_max = _require_integer(limits, "username_max_characters", username_min)
    password_min = _require_integer(limits, "password_min_characters", 1)
    _require_integer(limits, "password_max_utf8_bytes", password_min)
    authentication = _require_mapping(config, "authentication")
    _require_integer(authentication, "pbkdf2_iterations", 1)
    _require_integer(authentication, "legacy_pbkdf2_iterations", 1)
    _require_integer(authentication, "salt_bytes", 1)

    storage = _require_mapping(config, "storage")
    _require_text(storage, "users_database")
    _require_text(storage, "server_log")

    dlp = _require_mapping(config, "dlp")
    _require_number(dlp, "usage_fraction", 0.01, 1)
    _require_number(dlp, "block_minutes", 0.01)
    _require_number(dlp, "post_block_fraction", 0, 1)
    public_message = _require_text(dlp, "public_block_message")
    if "{minutes}" not in public_message:
        raise ValueError("dlp.public_block_message must contain '{minutes}'.")
    immediate_word = _require_text(dlp, "immediate_block_word")
    words = dlp.get("monitored_words")
    if not isinstance(words, list) or not words:
        raise ValueError("dlp.monitored_words must be a non-empty list.")
    if any(not isinstance(word, str) or not word.strip() for word in words):
        raise ValueError("Every monitored DLP word must be non-empty text.")
    if len(words) != len(set(words)):
        raise ValueError("dlp.monitored_words cannot contain duplicates.")
    if immediate_word not in words:
        raise ValueError("dlp.immediate_block_word must appear in monitored_words.")

    anti_bot = _require_mapping(config, "anti_bot")
    _require_number(anti_bot, "request_timeout_seconds", 0.1)
    _require_number(anti_bot, "cache_minutes", 0.01)
    _require_integer(anti_bot, "malicious_engines_to_block", 1)
    api_url = _require_text(anti_bot, "api_url")
    if "{address}" not in api_url:
        raise ValueError("anti_bot.api_url must contain '{address}'.")

    tls = _require_mapping(config, "tls")
    if _require_text(tls, "minimum_version") not in {"TLSv1_2", "TLSv1_3"}:
        raise ValueError("tls.minimum_version must be TLSv1_2 or TLSv1_3.")
    return config


def load_config(path=CONFIG_PATH):
    try:
        with Path(path).open(encoding="utf-8") as config_file:
            return validate_config(json.load(config_file))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"Cannot load configuration from {path}: {error}") from error


CONFIG = load_config()
NETWORK = CONFIG["network"]
LIMITS = CONFIG["limits"]
AUTHENTICATION = CONFIG["authentication"]
STORAGE = CONFIG["storage"]
DLP = CONFIG["dlp"]
ANTI_BOT = CONFIG["anti_bot"]
TLS = CONFIG["tls"]


def project_path(configured_path):
    path = Path(configured_path)
    return path if path.is_absolute() else PROJECT_ROOT / path
