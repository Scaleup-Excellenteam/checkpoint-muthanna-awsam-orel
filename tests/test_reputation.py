import io
import json
import os
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from chat import server as chat_server
from chat.auth import UserStore
from chat.reputation import ReputationDecision, VirusTotalChecker
from tests.helpers import read_messages


class ReputationTests(unittest.TestCase):
    def test_dotenv_key_is_used_in_request(self):
        report = {"data": {"attributes": {"last_analysis_stats": {"malicious": 0}}}}

        def open_report(request, timeout):
            self.assertEqual(request.get_header("X-apikey"), "test-key")
            return io.BytesIO(json.dumps(report).encode())

        with tempfile.TemporaryDirectory() as directory:
            env_path = Path(directory) / ".env"
            for value in ("test-key", "'test-key'", '"test-key"'):
                with self.subTest(value=value):
                    env_path.write_text(
                        f"# Local settings\n\nexport VIRUSTOTAL_API_KEY = {value} # comment\n",
                        encoding="utf-8-sig",
                    )
                    with patch("chat.config.ENV_PATH", env_path), patch.dict(os.environ, {}, clear=True):
                        checker = VirusTotalChecker(opener=open_report)
                        self.assertEqual(checker.status, "configured")
                        self.assertEqual(checker.check("8.8.8.8").verdict, "ALLOW")

    def test_environment_and_explicit_key_override_dotenv(self):
        with tempfile.TemporaryDirectory() as directory:
            env_path = Path(directory) / ".env"
            env_path.write_text("VIRUSTOTAL_API_KEY=file-key\n", encoding="utf-8")
            with patch("chat.config.ENV_PATH", env_path):
                for value in ("environment-key", ""):
                    with self.subTest(value=value), patch.dict(os.environ, {"VIRUSTOTAL_API_KEY": value}):
                        self.assertEqual(VirusTotalChecker().api_key, value)
                        self.assertEqual(VirusTotalChecker(api_key="explicit").api_key, "explicit")
                        self.assertEqual(VirusTotalChecker(api_key="").status, "not_configured")

    def test_missing_dotenv_keeps_key_optional(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch("chat.config.ENV_PATH", Path(directory) / ".env"), patch.dict(os.environ, {}, clear=True):
                self.assertEqual(VirusTotalChecker().status, "not_configured")

    def test_private_address_is_allowed_without_a_network_call(self):
        def fail_if_called(*args, **kwargs):
            raise AssertionError("VirusTotal must not be called for a private address")

        checker = VirusTotalChecker(api_key="secret", opener=fail_if_called)
        decision = checker.check("127.0.0.1")
        self.assertEqual(decision.verdict, "ALLOW")
        self.assertEqual(decision.reason, "local/private address")

    def test_missing_key_fails_open_without_a_network_call(self):
        def fail_if_called(*args, **kwargs):
            raise AssertionError("VirusTotal must not be called without an API key")

        checker = VirusTotalChecker(api_key="", opener=fail_if_called)
        decision = checker.check("8.8.8.8")
        self.assertEqual(decision.verdict, "UNKNOWN")
        self.assertTrue(decision.allowed)
        self.assertIn("not configured", decision.reason)

    def test_malicious_report_blocks_and_is_cached_for_ten_minutes(self):
        calls = []
        now = [10.0]
        report = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {"malicious": 1, "suspicious": 2},
                    "reputation": -7,
                }
            }
        }

        def open_report(request, timeout):
            calls.append((request, timeout))
            return io.BytesIO(json.dumps(report).encode())

        checker = VirusTotalChecker(
            api_key="secret",
            opener=open_report,
            clock=lambda: now[0],
            cache_seconds=600,
        )
        first = checker.check("8.8.8.8")
        second = checker.check("8.8.8.8")
        self.assertEqual(first.verdict, "BLOCK")
        self.assertEqual(first.malicious, 1)
        self.assertEqual(first.suspicious, 2)
        self.assertEqual(first.reputation, -7)
        self.assertEqual(second, first)
        self.assertEqual(len(calls), 1)

        now[0] += 600
        checker.check("8.8.8.8")
        self.assertEqual(len(calls), 2)

    def test_virustotal_failure_fails_open(self):
        def unavailable(*args, **kwargs):
            raise TimeoutError("offline")

        decision = VirusTotalChecker(api_key="secret", opener=unavailable).check(
            "8.8.8.8"
        )
        self.assertEqual(decision.verdict, "UNKNOWN")
        self.assertTrue(decision.allowed)
        self.assertIn("unavailable", decision.reason)

    def test_tcp_reputation_block_happens_before_authentication(self):
        class BlockingChecker:
            def check(self, address):
                return ReputationDecision("BLOCK", "malicious reputation", malicious=1)

        with tempfile.TemporaryDirectory() as directory, socket.socket() as listener:
            store = UserStore(Path(directory) / "users.db")
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            client = socket.create_connection(listener.getsockname(), timeout=5)
            connection, _ = listener.accept()
            thread = threading.Thread(
                target=chat_server.handle_client,
                args=(connection, store, None, BlockingChecker()),
                daemon=True,
            )
            thread.start()
            messages = read_messages(client)
            self.assertEqual(next(messages), "[ANTI-BOT] BLOCK: malicious reputation")
            self.assertIsNone(next(messages, None))
            messages.close()
            client.close()
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
            self.assertEqual(chat_server.active_clients, {})


if __name__ == "__main__":
    unittest.main()
