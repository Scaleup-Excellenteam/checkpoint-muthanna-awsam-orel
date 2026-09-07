"""Server-side DLP rules. These terms are never sent to chat clients."""

import math
import unicodedata


PIZZA_WORDS = frozenset({
    "פיצה",
    "בצק",
    "גבינה",
    "מוצרלה",
    "רוטב",
    "עגבנייה",
    "זיתים",
    "פטריות",
    "בצל",
    "תירס",
    "טונה",
    "פפרוני",
    "סלמי",
    "בזיליקום",
    "אורגנו",
    "שום",
    "קמח",
    "שמרים",
    "תנור",
    "מגש",
    "משולש",
    "תוספות",
    "קרום",
    "אפייה",
    "מרגריטה",
    "נפוליטנית",
    "קלצונה",
    "פרמזן",
    "ריקוטה",
    "אננס",
})

IMMEDIATE_BLOCK_WORD = "אננס"
USAGE_LIMIT = math.floor(len(PIZZA_WORDS) * 0.70)
BLOCK_SECONDS = 10 * 60
POST_BLOCK_CARRYOVER = math.ceil(USAGE_LIMIT * 0.50)
PUBLIC_BLOCK_MESSAGE = (
    "[SECURITY] Account blocked for 10 minutes: "
    "prohibited-word usage limit exceeded."
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
