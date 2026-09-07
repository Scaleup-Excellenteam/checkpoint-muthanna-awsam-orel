import contextlib
import io
import json
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from chat import server as chat_server
from chat import client
from chat.auth import UserStore
from chat.protocol import MAX_MESSAGE_BYTES, send_message
from tests.helpers import read_messages


class ClientIntegrationTests(unittest.TestCase):
    def test_interactive_client_authenticates_and_recovers_from_large_input(self):
        self.check_client_flow(
            ["2", "Alice", "room-a", "x" * 4097, "hello", "exit", "3"],
            sender="Alice",
            connections=2,
            feedback=f"Message exceeds {MAX_MESSAGE_BYTES} bytes",
        )

    def test_user_can_register_then_login_and_chat(self):
        self.check_client_flow(
            ["1", "NewUser", "2", "NewUser", "room-a", "hello", "exit", "3"],
            sender="NewUser", connections=3, feedback="Account created.",
        )

    def test_registration_password_mismatch_returns_to_menu_without_connecting(self):
        with patch("builtins.input", side_effect=["1", "NewUser", "3"]), \
             patch("getpass.getpass", side_effect=["first password", "second password"]), \
             patch("chat.client.socket.socket") as socket_factory, \
             contextlib.redirect_stdout(io.StringIO()) as output:
            client.start_client()
        socket_factory.return_value.connect.assert_not_called()
        self.assertIn("Passwords do not match", output.getvalue())

    def check_client_flow(self, inputs, sender, connections, feedback):
        with tempfile.TemporaryDirectory() as directory:
            store = UserStore(Path(directory) / "users.db")
            password = "temporary client test password"
            store.create_user("Alice", password)
            with socket.socket() as server:
                server.bind(("127.0.0.1", 0))
                server.listen()
                server.settimeout(5)
                threads = []

                def accept_clients():
                    for _ in range(connections):
                        connection, _ = server.accept()
                        thread = threading.Thread(target=chat_server.handle_client, args=(connection, store), daemon=True)
                        threads.append(thread)
                        thread.start()

                acceptor = threading.Thread(target=accept_clients, daemon=True)
                acceptor.start()
                try:
                    with socket.create_connection(server.getsockname(), timeout=5) as observer:
                        messages = read_messages(observer)
                        try:
                            self.assertEqual(
                                next(messages),
                                "[ANTI-BOT] ALLOW: local/private address",
                            )
                            send_message(observer, json.dumps({"username": "Alice", "password": password}))
                            self.assertEqual(next(messages), "[AUTH] OK")
                            send_message(observer, "room-a")
                            self.assertEqual(next(messages), "[ROOM] Joined room: room-a")
                            output = io.StringIO()
                            with patch("builtins.input", side_effect=inputs), \
                                 patch("getpass.getpass", return_value=password), contextlib.redirect_stdout(output):
                                client.start_client(*server.getsockname())
                            self.assertEqual(next(messages), f"{sender}: hello")
                            self.assertIn(feedback, output.getvalue())
                        finally:
                            observer.shutdown(socket.SHUT_RDWR)
                            messages.close()
                finally:
                    acceptor.join(timeout=5)
                    self.assertFalse(acceptor.is_alive())
                    for thread in threads:
                        thread.join(timeout=5)
                        self.assertFalse(thread.is_alive())
                self.assertEqual(chat_server.active_clients, {})


if __name__ == "__main__":
    unittest.main()
