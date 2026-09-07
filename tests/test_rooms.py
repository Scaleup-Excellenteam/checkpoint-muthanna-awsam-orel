import json
import select
import socket
import tempfile
import threading
import unittest
from pathlib import Path

from chat import server as chat_server
from chat.auth import UserStore
from chat.dlp import IMMEDIATE_BLOCK_WORD, PIZZA_WORDS, PUBLIC_BLOCK_MESSAGE, USAGE_LIMIT
from chat.protocol import MAX_AUTH_BYTES, MAX_MESSAGE_BYTES, MAX_ROOM_BYTES, send_message
from tests.helpers import read_messages


class RoomTests(unittest.TestCase):
    PASSWORD = "test-only long password"

    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.store = UserStore(Path(cls.directory.name) / "users.db")
        cls.store.create_user("Orel", cls.PASSWORD)
        cls.store.create_user("Alice", cls.PASSWORD)

    @classmethod
    def tearDownClass(cls):
        cls.directory.cleanup()

    def setUp(self):
        self.server = socket.socket()
        self.server.bind(("127.0.0.1", 0))
        self.server.listen()
        self.clients = []
        self.threads = []

    def tearDown(self):
        for client, messages in self.clients:
            try:
                client.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            messages.close()
            client.close()
        for thread in self.threads:
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
        self.server.close()
        self.assertEqual(chat_server.active_clients, {})

    def connect(self, room=None, username="Orel", authenticate=True):
        client = socket.create_connection(self.server.getsockname(), timeout=5)
        connection, _ = self.server.accept()
        thread = threading.Thread(target=chat_server.handle_client, args=(connection, self.store), daemon=True)
        thread.start()
        messages = read_messages(client)
        self.clients.append((client, messages))
        self.threads.append(thread)
        self.assertEqual(next(messages), "[ANTI-BOT] ALLOW: local/private address")
        if authenticate:
            send_message(client, json.dumps({"username": username, "password": self.PASSWORD}))
            self.assertEqual(next(messages), "[AUTH] OK")
        if room is not None:
            send_message(client, room)
            self.assertEqual(next(messages), f"[ROOM] Joined room: {room}")
        return client, messages

    def assert_quiet(self, *clients):
        ready, _, _ = select.select(clients, [], [], 0.1)
        self.assertEqual(ready, [])

    def test_messages_stay_in_room_and_skip_sender(self):
        sender, _ = self.connect("room-a")
        receiver, messages = self.connect("room-a")
        outsider, _ = self.connect("room-b")
        unjoined, _ = self.connect()

        send_message(sender, "hello")

        self.assertEqual(next(messages), "Orel: hello")
        self.assert_quiet(sender, outsider, unjoined)
        send_message(outsider, "Private message in room-b")
        self.assert_quiet(sender, receiver)

    def test_room_and_messages_can_arrive_together_or_in_parts(self):
        _, messages = self.connect("room-a")
        sender, replies = self.connect()
        payload = "room-a\nשלום\nsecond\n".encode("utf-8")
        # Split inside a multibyte Hebrew character.
        split = payload.index("ש".encode("utf-8")) + 1
        sender.sendall(payload[:split])
        sender.sendall(payload[split:])

        self.assertEqual(next(replies), "[ROOM] Joined room: room-a")
        self.assertEqual(next(messages), "Orel: שלום")
        self.assertEqual(next(messages), "Orel: second")

    def test_disconnect_removes_membership_and_room_can_be_reused(self):
        sender, _ = self.connect("room-a")
        sender.shutdown(socket.SHUT_RDWR)
        self.threads[0].join(timeout=2)
        self.assertEqual(chat_server.active_clients, {})

        sender, _ = self.connect("room-a")
        _, messages = self.connect("room-a")
        send_message(sender, "Still works")
        self.assertEqual(next(messages), "Orel: Still works")

    def test_empty_room_is_rejected(self):
        client, messages = self.connect()
        send_message(client, "   ")
        self.assertEqual(next(messages), "[ERROR] Room code cannot be empty.")
        self.assertIsNone(next(messages, None))

    def test_authentication_required_before_joining_room(self):
        client, messages = self.connect(authenticate=False)
        send_message(client, "room-a")
        self.assertEqual(next(messages), "[ERROR] Authentication failed.")
        self.assertIsNone(next(messages, None))
        self.assertEqual(chat_server.active_clients, {})

    def test_registration_persists_then_requires_login(self):
        client, messages = self.connect(authenticate=False)
        request = {"action": "register", "username": "NewUser", "password": self.PASSWORD}
        # A registration request must never authorize pipelined room/chat data.
        client.sendall((json.dumps(request) + "\nroom-a\nforged\n").encode())
        self.assertEqual(next(messages), "[REGISTER] OK")
        self.assertIsNone(next(messages, None))
        self.assertEqual(chat_server.active_clients, {})
        self.assertTrue(UserStore(self.store.path).authenticate("NewUser", self.PASSWORD))

        sender, _ = self.connect("room-a", username="NewUser")
        _, received = self.connect("room-a")
        send_message(sender, "hello")
        self.assertEqual(next(received), "NewUser: hello")

    def test_registration_cannot_replace_an_existing_password(self):
        client, messages = self.connect(authenticate=False)
        replacement = "different long password"
        send_message(client, json.dumps({"action": "register", "username": "Orel", "password": replacement}))
        self.assertEqual(next(messages), "[ERROR] Username already exists.")
        self.assertIsNone(next(messages, None))
        self.assertTrue(self.store.authenticate("Orel", self.PASSWORD))
        self.assertFalse(self.store.authenticate("Orel", replacement))

    def test_registration_rejects_invalid_fields(self):
        for username, password in [("InvalidUser", "short"), ("bad name", self.PASSWORD),
                                   ([], self.PASSWORD), ("InvalidUser", None),
                                   ("InvalidUser", "ש" * 129)]:
            with self.subTest(username=username):
                client, messages = self.connect(authenticate=False)
                send_message(client, json.dumps({"action": "register", "username": username, "password": password}))
                self.assertTrue(next(messages).startswith("[ERROR]"))
                self.assertIsNone(next(messages, None))
        self.assertFalse(self.store.authenticate("InvalidUser", self.PASSWORD))

    def test_competing_registrations_create_only_one_account(self):
        first, first_replies = self.connect(authenticate=False)
        second, second_replies = self.connect(authenticate=False)
        passwords = [self.PASSWORD, "another long test password"]
        for client, password in zip([first, second], passwords):
            send_message(client, json.dumps({"action": "register", "username": "UniqueUser", "password": password}))
        responses = [next(first_replies), next(second_replies)]
        self.assertCountEqual(responses, ["[REGISTER] OK", "[ERROR] Username already exists."])
        for index, password in enumerate(passwords):
            self.assertEqual(self.store.authenticate("UniqueUser", password), responses[index] == "[REGISTER] OK")
        self.assertIsNone(next(first_replies, None))
        self.assertIsNone(next(second_replies, None))

    def test_registration_frame_obeys_auth_size_limit(self):
        client, messages = self.connect(authenticate=False)
        payload = json.dumps({"action": "register", "username": "HugeUser", "password": "x" * MAX_AUTH_BYTES})
        client.sendall(payload.encode())
        self.assertEqual(next(messages), "[ERROR] Invalid or oversized message.")
        self.assertIsNone(next(messages, None))

    def test_wrong_password_and_unknown_user_have_same_response(self):
        for username, password in [("Orel", "wrong long password"), ("Nobody", self.PASSWORD)]:
            with self.subTest(username=username):
                client, messages = self.connect(authenticate=False)
                send_message(client, json.dumps({"username": username, "password": password}))
                self.assertEqual(next(messages), "[ERROR] Authentication failed.")
                self.assertIsNone(next(messages, None))

    def test_malformed_authentication_is_rejected(self):
        for credentials in [[], {"username": "Orel"}, {"username": [], "password": self.PASSWORD},
                            {"username": "Orel", "password": 123},
                            {"username": "Orel", "password": "\ud800" * 15},
                            {"action": "delete", "username": "Orel", "password": self.PASSWORD},
                            {"action": [], "username": "Orel", "password": self.PASSWORD},
                            {"action": "register", "username": "Orel"}]:
            with self.subTest(credentials=credentials):
                client, messages = self.connect(authenticate=False)
                send_message(client, json.dumps(credentials))
                self.assertEqual(next(messages), "[ERROR] Authentication failed.")
                self.assertIsNone(next(messages, None))

    def test_sender_identity_comes_from_authenticated_account(self):
        sender, _ = self.connect("room-a", username="Alice")
        _, messages = self.connect("room-a")
        send_message(sender, "Orel: forged")
        self.assertEqual(next(messages), "Alice: Orel: forged")

    def test_unauthenticated_client_cannot_receive_broadcast(self):
        sender, _ = self.connect("room-a")
        unverified, _ = self.connect(authenticate=False)
        send_message(sender, "hello")
        self.assert_quiet(unverified)

    def test_auth_room_and_chat_can_arrive_in_one_write(self):
        _, messages = self.connect("room-a")
        client, replies = self.connect(authenticate=False)
        auth = json.dumps({"username": "Orel", "password": self.PASSWORD})
        client.sendall((auth + "\nroom-a\nשלום\n").encode("utf-8"))
        self.assertEqual(next(replies), "[AUTH] OK")
        self.assertEqual(next(replies), "[ROOM] Joined room: room-a")
        self.assertEqual(next(messages), "Orel: שלום")

    def test_message_exact_byte_limit_including_hebrew(self):
        sender, _ = self.connect("room-a")
        _, messages = self.connect("room-a")
        for text in ["a" * MAX_MESSAGE_BYTES, "ש" * (MAX_MESSAGE_BYTES // 2)]:
            send_message(sender, text)
            self.assertEqual(next(messages), f"Orel: {text}")

    def test_oversized_chat_is_disconnected_without_newline(self):
        sender, replies = self.connect("room-a")
        receiver, messages = self.connect("room-a", username="Alice")
        observer, observed = self.connect("room-a")
        sender.sendall(b"a" * (MAX_MESSAGE_BYTES + 1))
        self.assertEqual(next(replies), "[ERROR] Invalid or oversized message.")
        self.assertIsNone(next(replies, None))
        self.assert_quiet(receiver, observer)
        send_message(receiver, "Still healthy")
        self.assertEqual(next(observed), "Alice: Still healthy")

    def test_room_byte_limit(self):
        self.connect("a" * MAX_ROOM_BYTES)
        client, messages = self.connect()
        client.sendall(b"a" * (MAX_ROOM_BYTES + 1))
        self.assertEqual(next(messages), "[ERROR] Invalid or oversized message.")
        self.assertIsNone(next(messages, None))

    def test_auth_size_is_limited_before_newline(self):
        client, messages = self.connect(authenticate=False)
        client.sendall(b"a" * (MAX_AUTH_BYTES + 1))
        self.assertEqual(next(messages), "[ERROR] Invalid or oversized message.")
        self.assertIsNone(next(messages, None))

    def test_invalid_utf8_and_terminal_controls_are_not_broadcast(self):
        receiver, _ = self.connect("room-a")
        for payload in [b"\xff\n", b"forged\rline\n", b"\x1b[2J\n"]:
            with self.subTest(payload=payload):
                sender, messages = self.connect("room-a")
                sender.sendall(payload)
                self.assertEqual(next(messages), "[ERROR] Invalid or oversized message.")
                self.assertIsNone(next(messages, None))
                self.assert_quiet(receiver)

    def test_dlp_is_silent_below_the_limit_and_preserves_original_text(self):
        self.store.create_user("SilentDlpUser", self.PASSWORD)
        sender, replies = self.connect("dlp-room", username="SilentDlpUser")
        receiver, received = self.connect("dlp-room", username="Alice")

        send_message(sender, "(פיצה)! stays unchanged")

        self.assertEqual(next(received), "SilentDlpUser: (פיצה)! stays unchanged")
        self.assert_quiet(sender)

    def test_pineapple_blocks_message_and_every_session_without_leaking_word(self):
        username = "ImmediateDlpUser"
        self.store.create_user(username, self.PASSWORD)
        triggering, triggering_replies = self.connect("dlp-room", username=username)
        _, other_replies = self.connect("other-room", username=username)
        observer, _ = self.connect("dlp-room", username="Alice")

        with self.assertLogs("chat.server", level="INFO") as captured:
            send_message(triggering, "private recipe: (אננס)!")
            first_public_reply = next(triggering_replies)
            second_public_reply = next(other_replies)

        self.assertEqual(first_public_reply, PUBLIC_BLOCK_MESSAGE)
        self.assertEqual(second_public_reply, PUBLIC_BLOCK_MESSAGE)
        self.assertNotIn(IMMEDIATE_BLOCK_WORD, first_public_reply)
        self.assertIsNone(next(triggering_replies, None))
        self.assertIsNone(next(other_replies, None))
        self.assert_quiet(observer)
        private_log = "\n".join(captured.output)
        self.assertIn(f"matched={IMMEDIATE_BLOCK_WORD}", private_log)
        self.assertIn("trigger=immediate_word", private_log)
        self.assertIn("recipients=0", private_log)

        blocked_client, blocked_replies = self.connect(authenticate=False)
        send_message(
            blocked_client,
            json.dumps({"username": username, "password": self.PASSWORD}),
        )
        blocked_login = next(blocked_replies)
        self.assertRegex(
            blocked_login,
            r"^\[ERROR\] Account temporarily blocked\. Try again in \d+ seconds\.$",
        )
        self.assertNotIn(IMMEDIATE_BLOCK_WORD, blocked_login)
        self.assertIsNone(next(blocked_replies, None))

    def test_word_22_is_not_delivered(self):
        username = "QuotaDlpUser"
        self.store.create_user(username, self.PASSWORD)
        terms = sorted(PIZZA_WORDS - {IMMEDIATE_BLOCK_WORD})
        initial = self.store.record_dlp_usage(username, terms[:USAGE_LIMIT])
        self.assertFalse(initial["blocked"])
        sender, replies = self.connect("quota-room", username=username)
        receiver, _ = self.connect("quota-room", username="Alice")

        send_message(sender, terms[USAGE_LIMIT])

        self.assertEqual(next(replies), PUBLIC_BLOCK_MESSAGE)
        self.assert_quiet(receiver)


if __name__ == "__main__":
    unittest.main()
