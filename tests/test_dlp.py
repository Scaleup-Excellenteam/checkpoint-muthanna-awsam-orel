import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from chat.auth import UserStore
from chat.dlp import (
    IMMEDIATE_BLOCK_WORD,
    PIZZA_WORDS,
    POST_BLOCK_CARRYOVER,
    USAGE_LIMIT,
    find_sensitive_words,
    normalize_words,
    requires_immediate_block,
)


class DlpTests(unittest.TestCase):
    PASSWORD = "a sufficiently long password"

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "users.db"
        self.now = [1_000.0]
        self.store = UserStore(self.path, clock=lambda: self.now[0])
        self.store.create_user("DlpUser", self.PASSWORD)

    def test_punctuation_and_niqqud_do_not_change_matching(self):
        for text in ["אננס", "אננס!", "(אננס)", "אננס,"]:
            with self.subTest(text=text):
                words = find_sensitive_words(text)
                self.assertEqual(words, {IMMEDIATE_BLOCK_WORD})
                self.assertTrue(requires_immediate_block(words))
        self.assertIn("פיצה", normalize_words("פִּיצָה!"))

    def test_limit_is_seventy_percent_of_the_server_list(self):
        self.assertEqual(len(PIZZA_WORDS), 30)
        self.assertEqual(USAGE_LIMIT, 21)
        self.assertEqual(POST_BLOCK_CARRYOVER, 11)

    def test_distinct_usage_blocks_on_word_22_and_persists(self):
        terms = sorted(PIZZA_WORDS - {IMMEDIATE_BLOCK_WORD})
        allowed = self.store.record_dlp_usage("DlpUser", terms[:USAGE_LIMIT])
        self.assertFalse(allowed["blocked"])
        self.assertEqual(allowed["after"], 21)

        repeated = self.store.record_dlp_usage("DlpUser", {terms[0]})
        self.assertFalse(repeated["blocked"])
        self.assertEqual(repeated["before"], 21)
        self.assertEqual(repeated["after"], 21)
        self.assertEqual(repeated["new_words"], set())

        blocked = self.store.record_dlp_usage("DlpUser", {terms[USAGE_LIMIT]})
        self.assertTrue(blocked["blocked"])
        self.assertEqual(blocked["after"], 22)
        self.assertEqual(blocked["reason"], "usage_limit")

        reopened = UserStore(self.path, clock=lambda: self.now[0])
        authenticated, remaining = reopened.login_status("DlpUser", self.PASSWORD)
        self.assertFalse(authenticated)
        self.assertEqual(remaining, 600)

        self.now[0] += 601
        authenticated, remaining = reopened.login_status("DlpUser", self.PASSWORD)
        self.assertTrue(authenticated)
        self.assertEqual(remaining, 0)
        after_release = reopened.record_dlp_usage("DlpUser", {terms[0]})
        self.assertEqual(after_release["before"], POST_BLOCK_CARRYOVER)
        self.assertEqual(after_release["after"], POST_BLOCK_CARRYOVER + 1)

    def test_pineapple_blocks_immediately(self):
        result = self.store.record_dlp_usage(
            "DlpUser", {IMMEDIATE_BLOCK_WORD}, immediate_block=True
        )
        self.assertTrue(result["blocked"])
        self.assertEqual(result["reason"], "immediate_word")
        self.assertEqual(result["blocked_until"], 1_600.0)

    def test_existing_database_is_migrated(self):
        old_path = Path(self.directory.name) / "old-users.db"
        with closing(sqlite3.connect(old_path)) as connection:
            connection.execute(
                "CREATE TABLE users (username TEXT PRIMARY KEY, salt BLOB NOT NULL, "
                "password_hash BLOB NOT NULL)"
            )
            connection.commit()
        UserStore(old_path)
        with closing(sqlite3.connect(old_path)) as connection:
            columns = {row[1] for row in connection.execute("PRAGMA table_info(users)")}
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
        self.assertIn("blocked_until", columns)
        self.assertIn("dlp_carryover", columns)
        self.assertIn("password_iterations", columns)
        self.assertIn("dlp_words", tables)


if __name__ == "__main__":
    unittest.main()
