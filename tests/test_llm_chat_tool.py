"""Runner integration tests: real REST server, temporary database, fake Ollama HTTP API."""

import contextlib
import io
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from chat.api import create_api_server
from chat.auth import UserStore, password_hash
from chat.dlp import IMMEDIATE_BLOCK_WORD, PIZZA_WORDS, USAGE_LIMIT
from chat.protocol import MAX_MESSAGE_BYTES
from tools.llm_chat_test import Agent, ChatRun, RunError, build_parser, main


class FakeOllamaHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.reply(200, {"models": [{"name": name} for name in self.server.models]})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        self.server.requests.append(body)
        if self.server.delay:
            time.sleep(self.server.delay)
        if self.server.invalid_json:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"not json")
            return
        text = self.server.text
        if text is None:
            text = f"נלך יחד בפארק ונשוחח בדרך {len(self.server.requests)}."
        self.reply(200, {"done": True, "message": {"role": "assistant", "content": text}})

    def reply(self, status, body):
        payload = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        try:
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError):
            pass

    def log_message(self, *args):
        pass


class LlmChatToolTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        # The runner still uses real registration/login; reduce only this test store's work factor.
        iterations = patch("chat.auth.PASSWORD_ITERATIONS", 1000)
        iterations.start()
        self.addCleanup(iterations.stop)
        hashing = patch("chat.auth.password_hash", side_effect=lambda password, salt, iterations=1000:
                        password_hash(password, salt, iterations))
        hashing.start()
        self.addCleanup(hashing.stop)
        self.store = UserStore(self.directory / "users.db")
        self.api = create_api_server(self.store, port=0)
        self.start(self.api)
        self.ollama = ThreadingHTTPServer(("127.0.0.1", 0), FakeOllamaHandler)
        self.ollama.models = ["qwen3:1.7b"]
        self.ollama.requests = []
        self.ollama.text = None
        self.ollama.delay = 0
        self.ollama.invalid_json = False
        self.start(self.ollama)

    def start(self, server):
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True)
        thread.start()

        def stop():
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.addCleanup(stop)

    def runner(self, scenario="chat", messages=4, extra=()):
        args = build_parser().parse_args([
            "--scenario", scenario, "--messages", str(messages), "--no-pause",
            "--server-url", f"http://127.0.0.1:{self.api.server_port}",
            "--ollama-url", f"http://127.0.0.1:{self.ollama.server_port}",
            "--output-dir", str(self.directory / "reports"),
            "--delivery-timeout", "1", "--poll-interval", "0.05", *extra,
        ])
        return ChatRun(args)

    def execute(self, run):
        with contextlib.redirect_stdout(io.StringIO()):
            code = run.execute()
        report = json.loads((run.directory / "report.json").read_text(encoding="utf-8"))
        self.assertEqual(report["exit_code"], code)
        return code, report

    def user_count(self):
        with contextlib.closing(sqlite3.connect(self.store.path)) as connection:
            return connection.execute("SELECT COUNT(*) FROM users").fetchone()[0]

    def test_full_run_20_turns_and_security_through_real_http(self):
        run = self.runner("all", 20)
        code, report = self.execute(run)
        self.assertEqual(code, 0, report)
        self.assertEqual([r["status"] for r in report["results"]], ["passed"] * 4)
        self.assertEqual(self.user_count(), 8)
        self.assertEqual(len({r["room"] for r in report["results"]}), 4)
        self.assertEqual(self.api.sessions, {})
        chat = [e for e in report["events"] if e["scenario"] == "chat"]
        self.assertEqual(len(chat), 20)
        self.assertEqual(len({e["message_id"] for e in chat}), 20)
        self.assertEqual([e["message_id"] for e in chat], sorted(e["message_id"] for e in chat))
        self.assertEqual(chat[0]["sender"], chat[1]["receiver"])
        self.assertEqual(chat[0]["receiver"], chat[1]["sender"])
        for index, request in enumerate(self.ollama.requests):
            self.assertFalse(request["stream"])
            self.assertFalse(request["think"])
            self.assertEqual(request["options"]["num_predict"], 150)
            self.assertLessEqual(len(request["messages"]), 11)
            prompt = request["messages"][0]["content"]
            self.assertFalse(any(word in prompt for word in PIZZA_WORDS))
            if index:
                self.assertEqual(request["messages"][-1], {"role": "user", "content": chat[index - 1]["text"]})
        self.assertNotEqual(self.ollama.requests[0]["messages"][0], self.ollama.requests[1]["messages"][0])
        boundary = [e for e in report["events"] if e["scenario"] == "size"]
        self.assertEqual(len(boundary[0]["text"].encode("utf-8")), MAX_MESSAGE_BYTES)
        self.assertEqual(len(boundary[1]["text"].encode("utf-8")), MAX_MESSAGE_BYTES + 1)
        self.assertEqual([e["http_status"] for e in boundary], [201, 413, 201, 201])
        quota = [e for e in report["events"] if e["scenario"] == "quota"]
        self.assertEqual(quota[0]["text"], quota[1]["text"])
        self.assertEqual(len(quota), USAGE_LIMIT + 2)
        self.assertEqual(quota[-1]["http_status"], 403)
        self.assertTrue(report["results"][2]["session_revoked"])
        self.assertTrue(report["results"][3]["session_revoked"])

    def test_missing_model_stops_before_creating_any_accounts(self):
        self.ollama.models = []
        code, report = self.execute(self.runner())
        self.assertEqual(code, 2)
        self.assertEqual(self.user_count(), 0)
        self.assertEqual(report["stop_reason"]["source"], "model")

    def test_security_does_not_require_ollama(self):
        run = self.runner("security")
        with patch.object(run.model, "preflight", side_effect=AssertionError("Must not contact Ollama")):
            code, _ = self.execute(run)
        self.assertEqual(code, 0)
        self.assertEqual(self.ollama.requests, [])

    def test_accepted_but_missing_delivery_fails_without_next_model_turn(self):
        with patch.object(self.api, "publish_message", return_value=0):
            code, report = self.execute(self.runner())
        self.assertEqual(code, 1)
        self.assertEqual(len(self.ollama.requests), 1)
        self.assertIn("deadline", report["stop_reason"]["reason"])
        self.assertEqual(self.api.sessions, {})

    def test_changed_message_or_sender_cannot_pass_delivery_check(self):
        original = self.api.publish_message
        for change_sender in (False, True):
            with self.subTest(change_sender=change_sender):
                def corrupt(room, username, text):
                    return original(room, "WrongUser" if change_sender else username,
                                    text if change_sender else "modified")

                with patch.object(self.api, "publish_message", side_effect=corrupt):
                    code, _ = self.execute(self.runner())
                self.assertEqual(code, 1)

    def test_duplicate_delivery_is_a_failure(self):
        original = self.api.publish_message

        def duplicate(room, username, text):
            original(room, username, text)
            return original(room, username, text)

        with patch.object(self.api, "publish_message", side_effect=duplicate):
            code, report = self.execute(self.runner())
        self.assertEqual(code, 1)
        self.assertIn("duplicates", report["stop_reason"]["reason"])
        self.assertEqual(len(self.ollama.requests), 1)

    def test_observer_messages_are_not_added_to_agent_history(self):
        original = self.api.publish_message

        def add_observer(room, username, text):
            original(room, "Observer", "OBSERVER_MARKER")
            return original(room, username, text)

        with patch.object(self.api, "publish_message", side_effect=add_observer):
            code, _ = self.execute(self.runner())
        self.assertEqual(code, 0)
        self.assertNotIn("OBSERVER_MARKER", json.dumps(self.ollama.requests))

    def test_stale_poll_results_do_not_repeat_a_turn_and_bad_order_fails(self):
        run = self.runner()
        run.room = "test"
        agent = Agent("Receiver", "token", cursor=5)
        stale = {"id": 5, "username": "Sender", "text": "old"}
        fresh = {"id": 6, "username": "Sender", "text": "new"}
        with patch.object(run.api, "request", return_value=(200, {"messages": [stale, fresh]})):
            self.assertEqual(run.poll(agent), [fresh])
            self.assertEqual(run.poll(agent), [])
        self.assertEqual(agent.cursor, 6)
        with patch.object(run.api, "request", return_value=(200, {"messages": [dict(fresh, id=8), dict(fresh, id=7)]})):
            with self.assertRaisesRegex(RunError, "out-of-order"):
                run.poll(agent)

    def test_empty_invalid_and_oversized_model_responses_are_infrastructure_errors(self):
        for text in ("", " ", "א" * MAX_MESSAGE_BYTES):
            with self.subTest(text_length=len(text)):
                self.ollama.text = text
                code, report = self.execute(self.runner())
                self.assertEqual(code, 2)
                self.assertEqual(report["stop_reason"]["source"], "model")
                self.assertEqual(report["events"], [])
        self.ollama.invalid_json = True
        code, report = self.execute(self.runner())
        self.assertEqual(code, 2)
        self.assertEqual(report["stop_reason"]["source"], "model")

    def test_model_timeout_is_reported_without_retry(self):
        self.ollama.delay = 0.3
        code, report = self.execute(self.runner(extra=("--model-timeout", "0.1")))
        self.assertEqual(code, 2)
        self.assertEqual(report["stop_reason"]["source"], "model")
        self.assertEqual(len(self.ollama.requests), 1)
        self.assertEqual(self.api.sessions, {})

    def test_uncertain_post_is_not_retried_and_partial_transcript_is_saved(self):
        run = self.runner()
        original = run.api.request
        attempts = []

        def lose_ack(method, path, *args, **kwargs):
            result = original(method, path, *args, **kwargs)
            if method == "POST" and path.endswith("/messages"):
                attempts.append(path)
                raise RunError("Connection lost after send.", "connection", 2)
            return result

        with patch.object(run.api, "request", side_effect=lose_ack):
            code, report = self.execute(run)
        self.assertEqual(code, 2)
        self.assertEqual(len(attempts), 1)
        self.assertEqual(report["events"][0]["outcome"], "incomplete")
        self.assertIn(report["events"][0]["text"], (run.directory / "transcript.txt").read_text(encoding="utf-8"))

    def test_unexpected_dlp_block_is_a_chat_failure(self):
        self.ollama.text = IMMEDIATE_BLOCK_WORD
        code, report = self.execute(self.runner())
        self.assertEqual(code, 1)
        self.assertEqual(report["events"][0]["http_status"], 403)
        self.assertEqual(report["stop_reason"]["source"], "chat")

    def test_blocked_message_leaking_to_receiver_fails_security_checks(self):
        run = self.runner("security")
        original = run.api.request

        def leak_rejected_message(method, path, data=None, token=None, **kwargs):
            status, body = original(method, path, data, token, **kwargs)
            if method == "POST" and path.endswith("/messages") and status == 403:
                self.api.publish_message(run.room, run.agents[0].username, data["message"])
            return status, body

        with patch.object(run.api, "request", side_effect=leak_rejected_message):
            code, report = self.execute(run)
        self.assertEqual(code, 1)
        self.assertEqual([r["status"] for r in report["results"]], ["passed", "failed", "failed"])
        self.assertIn("Rejected message was delivered", report["stop_reason"]["reason"])

    def test_limit_mismatch_stops_before_creating_accounts(self):
        run = self.runner()
        original = run.api.request

        def mismatch(method, path, *args, **kwargs):
            status, body = original(method, path, *args, **kwargs)
            if path == "/ui-config":
                body["message_bytes"] += 1
            return status, body

        with patch.object(run.api, "request", side_effect=mismatch):
            code, report = self.execute(run)
        self.assertEqual(code, 2)
        self.assertEqual(report["stop_reason"]["source"], "configuration")
        self.assertEqual(self.user_count(), 0)

    def test_ctrl_c_and_closed_input_cleanup_and_write_incomplete_report(self):
        for error in (KeyboardInterrupt, EOFError):
            with self.subTest(error=error):
                run = self.runner()
                run.args.no_pause = False
                with patch("builtins.input", side_effect=error):
                    code, report = self.execute(run)
                self.assertEqual(code, 2)
                self.assertEqual(report["results"][0]["status"], "incomplete")
                self.assertEqual(self.api.sessions, {})

    def test_passwords_and_tokens_are_not_written_to_artifacts(self):
        passwords, tokens = [], []
        create_user, create_session = self.store.create_user, self.api.create_session

        def capture_user(username, password):
            passwords.append(password)
            return create_user(username, password)

        def capture_session(username):
            token = create_session(username)
            tokens.append(token)
            return token

        run = self.runner()
        with patch.object(self.store, "create_user", side_effect=capture_user), \
                patch.object(self.api, "create_session", side_effect=capture_session):
            code, _ = self.execute(run)
        self.assertEqual(code, 0)
        artifacts = "".join(p.read_text(encoding="utf-8") for p in run.directory.iterdir())
        for secret in passwords + tokens:
            self.assertNotIn(secret, artifacts)

    def test_unavailable_server_returns_exit_2_and_report(self):
        run = self.runner()
        with patch.object(run.api, "request", side_effect=RunError("Server unavailable", "connection", 2)):
            code, report = self.execute(run)
        self.assertEqual(code, 2)
        self.assertEqual(report["status"], "incomplete")
        self.assertEqual(self.user_count(), 0)

    def test_cli_rejects_invalid_limits_and_credential_urls(self):
        for args in (("--messages", "0"), ("--delivery-timeout", "nan"),
                     ("--model-timeout", "inf"), ("--server-url", "http://user:secret@localhost")):
            with self.subTest(args=args), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    main(args)
                self.assertEqual(caught.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
