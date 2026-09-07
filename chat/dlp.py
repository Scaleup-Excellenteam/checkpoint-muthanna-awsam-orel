"""Server-side DLP rules. These terms are never sent to chat clients."""

import math
import unicodedata
from datetime import timedelta

from .config import DLP


PIZZA_WORDS = frozenset(DLP["monitored_words"])
IMMEDIATE_BLOCK_WORD = DLP["immediate_block_word"]
USAGE_LIMIT = math.floor(len(PIZZA_WORDS) * DLP["usage_fraction"])
BLOCK_SECONDS = timedelta(minutes=DLP["block_minutes"]).total_seconds()
POST_BLOCK_CARRYOVER = math.ceil(USAGE_LIMIT * DLP["post_block_fraction"])
PUBLIC_BLOCK_MESSAGE = DLP["public_block_message"].format(
    minutes=DLP["block_minutes"]
)


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


def find_sensitive_words(message):
    """Return distinct monitored words found in a message."""
    return set(normalize_words(message)) & PIZZA_WORDS


def requires_immediate_block(words):
    return IMMEDIATE_BLOCK_WORD in words
