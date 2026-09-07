"""Newline-delimited UTF-8 frames, bounded before decoding or buffering."""

import unicodedata

from .config import LIMITS


MAX_MESSAGE_BYTES = LIMITS["message_bytes"]
MAX_ROOM_BYTES = LIMITS["room_bytes"]
MAX_AUTH_BYTES = LIMITS["auth_bytes"]
MAX_SERVER_MESSAGE_BYTES = (
    MAX_MESSAGE_BYTES
    + LIMITS["username_max_characters"]
    + len(": ".encode("utf-8"))
)


class ProtocolError(ValueError):
    pass


class MessageTooLarge(ProtocolError):
    pass


def validate_text(message):
    """Prevent line and terminal-control injection in displayed messages."""
    for char in message:
        if unicodedata.category(char) == "Cc":
            raise ProtocolError("Control characters are not allowed.")


def send_message(client_socket, message, max_bytes=MAX_SERVER_MESSAGE_BYTES):
    validate_text(message)
    payload = message.encode("utf-8")
    if len(payload) > max_bytes:
        raise MessageTooLarge(f"Message exceeds {max_bytes} bytes.")
    client_socket.sendall(payload + b"\n")


def read_message(stream, max_bytes=MAX_MESSAGE_BYTES):
    """Read one bounded line; return None when the connection ends."""
    # The extra byte is for '\n'. Reading stays bounded even without it.
    line = stream.readline(max_bytes + 1)
    if not line:
        return None
    if not line.endswith(b"\n"):
        if len(line) > max_bytes:
            raise MessageTooLarge(f"Message exceeds {max_bytes} bytes.")
        raise ProtocolError("Incomplete message.")
    message = line[:-1].decode("utf-8")
    validate_text(message)
    return message
