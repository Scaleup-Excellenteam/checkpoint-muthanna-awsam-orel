import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from chat.auth import UserStore


class AuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "users.db"
        self.store = UserStore(self.path)

    def test_persistent_accounts_and_salted_hashes(self):
        password = "a test password with spaces"
        self.store.create_user("Alice", password)
        self.store.create_user("Bobby", password)
        with closing(sqlite3.connect(self.path)) as connection:
            rows = connection.execute("SELECT salt, password_hash FROM users").fetchall()
        self.assertNotEqual(rows[0][0], rows[1][0])
        self.assertNotEqual(rows[0][1], rows[1][1])
        self.assertNotIn(password.encode(), self.path.read_bytes())
        reopened = UserStore(self.path)
        self.assertTrue(reopened.authenticate("Alice", password))
        self.assertFalse(reopened.authenticate("Alice", "a different password"))
        self.assertFalse(reopened.authenticate("Nobody", password))

    def test_existing_account_cannot_be_overwritten(self):
        self.store.create_user("Alice", "original long password")
        with self.assertRaises(ValueError):
            self.store.create_user("Alice", "replacement password")
        self.assertTrue(self.store.authenticate("Alice", "original long password"))

    def test_account_validation(self):
        for username, password in [("ab", "a sufficiently long password"),
                                   ("Alice\nBob", "a sufficiently long password"),
                                   ("Alice", "1234567"), ("Alice", "ש" * 129)]:
            with self.subTest(username=username, length=len(password)):
                with self.assertRaises(ValueError):
                    self.store.create_user(username, password)

    def test_eight_character_password_is_allowed(self):
        self.store.create_user("EightChar", "12345678")
        self.assertTrue(self.store.authenticate("EightChar", "12345678"))


if __name__ == "__main__":
    unittest.main()
