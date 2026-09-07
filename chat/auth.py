"""Register and authenticate service users; store only salted password hashes."""

import hashlib
import hmac
import json
import re
import secrets
import sqlite3
import logging
import math
import time
from contextlib import closing
from pathlib import Path

from .dlp import BLOCK_SECONDS, POST_BLOCK_CARRYOVER, USAGE_LIMIT

DEFAULT_USERS_DB = Path(__file__).resolve().parent.parent / "data" / "users.db"
PASSWORD_ITERATIONS = 600_000
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_BYTES = 256
USERNAME_PATTERN = re.compile(r"[A-Za-z0-9_-]{3,32}\Z")
logger = logging.getLogger(__name__)


def valid_username(username):
    if not isinstance(username, str):
        return False
    return USERNAME_PATTERN.fullmatch(username) is not None


def valid_password(password):
    if not isinstance(password, str):
        return False
    try:
        byte_count = len(password.encode("utf-8"))
    except UnicodeError:
        return False
    return len(password) >= MIN_PASSWORD_LENGTH and byte_count <= MAX_PASSWORD_BYTES


def password_hash(password, salt):
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PASSWORD_ITERATIONS)


class UserStore:
    def __init__(self, path=DEFAULT_USERS_DB, clock=time.time):
        self.path = Path(path)
        self.clock = clock
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS users "
                "(username TEXT PRIMARY KEY, salt BLOB NOT NULL, password_hash BLOB NOT NULL, "
                "blocked_until REAL NOT NULL DEFAULT 0, dlp_carryover INTEGER NOT NULL DEFAULT 0)"
            )
            columns = {row[1] for row in connection.execute("PRAGMA table_info(users)")}
            if "blocked_until" not in columns:
                connection.execute(
                    "ALTER TABLE users ADD COLUMN blocked_until REAL NOT NULL DEFAULT 0"
                )
            if "dlp_carryover" not in columns:
                connection.execute(
                    "ALTER TABLE users ADD COLUMN dlp_carryover INTEGER NOT NULL DEFAULT 0"
                )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS dlp_words "
                "(username TEXT NOT NULL, word TEXT NOT NULL, "
                "PRIMARY KEY (username, word))"
            )
            connection.commit()
        # Missing accounts still perform the same expensive verification.
        self._dummy_salt = secrets.token_bytes(16)
        self._dummy_hash = secrets.token_bytes(32)

    def create_user(self, username, password):
        if not valid_username(username):
            raise ValueError("Username must contain 3-32 ASCII letters, digits, '_' or '-'.")
        if not valid_password(password):
            raise ValueError("Password must contain at least 8 characters and at most 256 UTF-8 bytes.")
        salt = secrets.token_bytes(16)
        digest = password_hash(password, salt)
        try:
            with closing(sqlite3.connect(self.path)) as connection:
                connection.execute(
                    "INSERT INTO users (username, salt, password_hash) VALUES (?, ?, ?)",
                    (username, salt, digest),
                )
                connection.commit()
        except sqlite3.IntegrityError:
            raise ValueError("Username already exists.") from None

    def authenticate(self, username, password):
        authenticated, _ = self.login_status(username, password)
        return authenticated

    def login_status(self, username, password):
        """Return (authenticated, seconds blocked) without revealing unknown users."""
        if not valid_username(username) or not valid_password(password):
            return False, 0
        with closing(sqlite3.connect(self.path)) as connection:
            record = connection.execute(
                "SELECT salt, password_hash FROM users WHERE username = ?", (username,)
            ).fetchone()
        if record is None:
            salt, expected = self._dummy_salt, self._dummy_hash
        else:
            salt, expected = record
        matches = hmac.compare_digest(password_hash(password, salt), expected)
        if record is None or not matches:
            return False, 0
        remaining, _ = self.block_status(username)
        return remaining == 0, remaining

    def block_status(self, username):
        """Return (seconds remaining, released now), resetting DLP after expiry."""
        now = self.clock()
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT blocked_until FROM users WHERE username = ?", (username,)
            ).fetchone()
            if row is None or row[0] <= 0:
                connection.commit()
                return 0, False
            blocked_until = float(row[0])
            if blocked_until > now:
                connection.commit()
                return max(1, math.ceil(blocked_until - now)), False
            connection.execute(
                "UPDATE users SET blocked_until = 0, dlp_carryover = ? WHERE username = ?",
                (POST_BLOCK_CARRYOVER, username),
            )
            connection.execute("DELETE FROM dlp_words WHERE username = ?", (username,))
            connection.commit()
        logger.info(
            "event=account_unblocked username=%s released_at=%.3f "
            "previous_block_end=%.3f dlp_carryover=%d",
            username,
            now,
            blocked_until,
            POST_BLOCK_CARRYOVER,
        )
        return 0, True

    def record_dlp_usage(self, username, matched_words, immediate_block=False):
        """Atomically update one user's distinct-word usage and block if required."""
        now = self.clock()
        matched_words = set(matched_words)
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT blocked_until, dlp_carryover FROM users WHERE username = ?",
                (username,),
            ).fetchone()
            if row is None:
                connection.rollback()
                raise ValueError("Unknown username.")

            blocked_until, carryover = float(row[0]), int(row[1])
            if blocked_until > now:
                before = carryover + self._dlp_word_count(connection, username)
                connection.commit()
                return self._dlp_result(
                    before, before, set(), True, "already_blocked", blocked_until
                )
            if blocked_until > 0:
                carryover = POST_BLOCK_CARRYOVER
                connection.execute(
                    "UPDATE users SET blocked_until = 0, dlp_carryover = ? WHERE username = ?",
                    (carryover, username),
                )
                connection.execute("DELETE FROM dlp_words WHERE username = ?", (username,))
                logger.info(
                    "event=account_unblocked username=%s released_at=%.3f "
                    "previous_block_end=%.3f dlp_carryover=%d",
                    username,
                    now,
                    blocked_until,
                    POST_BLOCK_CARRYOVER,
                )

            before = carryover + self._dlp_word_count(connection, username)
            new_words = set()
            for word in sorted(matched_words):
                cursor = connection.execute(
                    "INSERT OR IGNORE INTO dlp_words (username, word) VALUES (?, ?)",
                    (username, word),
                )
                if cursor.rowcount:
                    new_words.add(word)
            after = carryover + self._dlp_word_count(connection, username)
            blocked = immediate_block or after > USAGE_LIMIT
            reason = "immediate_word" if immediate_block else "usage_limit"
            if blocked:
                blocked_until = now + BLOCK_SECONDS
                connection.execute(
                    "UPDATE users SET blocked_until = ? WHERE username = ?",
                    (blocked_until, username),
                )
            connection.commit()
        return self._dlp_result(
            before,
            after,
            new_words,
            blocked,
            reason if blocked else "allowed",
            blocked_until if blocked else 0,
        )

    @staticmethod
    def _dlp_word_count(connection, username):
        return connection.execute(
            "SELECT COUNT(*) FROM dlp_words WHERE username = ?", (username,)
        ).fetchone()[0]

    @staticmethod
    def _dlp_result(before, after, new_words, blocked, reason, blocked_until=0):
        return {
            "before": before,
            "after": after,
            "new_words": new_words,
            "blocked": blocked,
            "reason": reason,
            "limit": USAGE_LIMIT,
            "blocked_until": blocked_until,
        }

    def check_health(self):
        """Raise an error if the user database cannot answer a simple query."""
        with closing(sqlite3.connect(self.path)) as connection:
            connection.execute("SELECT 1").fetchone()

    def handle_request(self, message):
        """Return (logged-in username or None, reply) for registration or login."""
        failure = (None, "[ERROR] Authentication failed.")
        if message is None:
            return failure
        try:
            credentials = json.loads(message)
        except (ValueError, RecursionError):
            return failure
        if not isinstance(credentials, dict):
            return failure
        keys = set(credentials)
        if keys != {"username", "password"} and keys != {"action", "username", "password"}:
            return failure
        # Older clients send only username/password; that still means login.
        action = credentials.get("action", "login")
        if action not in ("register", "login"):
            return failure
        username = credentials["username"]
        password = credentials["password"]
        if action == "register":
            try:
                self.create_user(username, password)
            except ValueError as error:
                return None, f"[ERROR] {error}"
            # Creating an account does not log the connection into a room.
            return None, "[REGISTER] OK"
        authenticated, blocked_seconds = self.login_status(username, password)
        if blocked_seconds:
            return None, (
                "[ERROR] Account temporarily blocked. "
                f"Try again in {blocked_seconds} seconds."
            )
        if authenticated:
            return username, "[AUTH] OK"
        return failure
