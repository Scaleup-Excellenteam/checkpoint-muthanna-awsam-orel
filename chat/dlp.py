"""Server-side DLP rules. These terms are never sent to chat clients."""

import math
import unicodedata
from datetime import timedelta

from .config import DLP


def normalize_words(message):
    """Return lowercase words while ignoring punctuation and Hebrew niqqud."""
    normalized = unicodedata.normalize("NFKD", message).casefold()
    characters = []
    for character in normalized:
        category = unicodedata.category(character)
        if category.startswith(("L", "N")):
            characters.append(character)
        elif category.startswith("M"):
            # Combining marks include Hebrew niqqud; ignore them without
            # splitting the word around them.
            continue
        else:
            characters.append(" ")
    return characters_to_words(characters)


def characters_to_words(characters):
    return tuple("".join(characters).split())


def _normalize_configured_word(word):
    normalized = normalize_words(word)
    if len(normalized) != 1:
        raise ValueError("Every configured DLP entry must normalize to one word.")
    return normalized[0]


_normalized_words = [_normalize_configured_word(word) for word in DLP["monitored_words"]]
if len(_normalized_words) != len(set(_normalized_words)):
    raise ValueError("Configured DLP words must be unique after normalization.")

PIZZA_WORDS = frozenset(_normalized_words)
IMMEDIATE_BLOCK_WORD = _normalize_configured_word(DLP["immediate_block_word"])
if IMMEDIATE_BLOCK_WORD not in PIZZA_WORDS:
    raise ValueError("The immediate-block word must be part of the DLP vocabulary.")
USAGE_LIMIT = math.floor(len(PIZZA_WORDS) * DLP["usage_fraction"])
BLOCK_SECONDS = timedelta(minutes=DLP["block_minutes"]).total_seconds()
POST_BLOCK_CARRYOVER = math.ceil(USAGE_LIMIT * DLP["post_block_fraction"])
PUBLIC_BLOCK_MESSAGE = DLP["public_block_message"].format(
    minutes=DLP["block_minutes"]
)


def find_sensitive_words(message):
    """Return distinct monitored words found in a message."""
    return set(normalize_words(message)) & PIZZA_WORDS


def requires_immediate_block(words):
    return IMMEDIATE_BLOCK_WORD in words
