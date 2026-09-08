"""Real TLS tests using temporary certificates, when OpenSSL is available."""

import json
import http.client
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

from chat import server as chat_server
from chat.api import create_api_server
from chat.auth import UserStore
from chat.protocol import send_message
from chat.reputation import VirusTotalChecker
from tests.helpers import read_messages
from chat.transport import client_context, server_context


class TLSIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        openssl = shutil.which("openssl")
        if not openssl:
            bundled = Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Git/usr/bin/openssl.exe"
            if bundled.is_file():
                openssl = str(bundled)
        if not openssl:
            raise unittest.SkipTest("OpenSSL is required to generate temporary TLS test certificates.")
        cls.directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.directory.cleanup)
        root = Path(cls.directory.name)
        cls.cert = root / "test-cert.pem"
        key = root / "test-key.pem"
        subprocess.run(
            [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
             "-keyout", str(key), "-out", str(cls.cert), "-subj", "/CN=localhost",
             "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
            check=True, capture_output=True, timeout=30,
        )
        cls.context = server_context("127.0.0.1", cls.cert, key)
        cls.store = UserStore(root / "users.db")
        cls.password = "temporary TLS test password"
        cls.store.create_user("Alice", cls.password)

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
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
        self.server.close()
        self.assertEqual(chat_server.active_clients, {})

    def connect(self, trusted=True, hostname="localhost", username="Alice", register=False):
        context = client_context("127.0.0.1", tls=True, cafile=str(self.cert) if trusted else None)
        client = socket.create_connection(self.server.getsockname(), timeout=5)
        connection, _ = self.server.accept()
        thread = threading.Thread(target=chat_server.handle_client, args=(connection, self.store, self.context), daemon=True)
        self.threads.append(thread)
        thread.start()
        try:
            client = context.wrap_socket(client, server_hostname=hostname)
        except OSError:
            client.close()
            raise
        messages = read_messages(client)
        self.clients.append((client, messages))
        self.assertEqual(next(messages), "[ANTI-BOT] ALLOW: local/private address")
        action = "register" if register else "login"
        send_message(client, json.dumps({"action": action, "username": username, "password": self.password}))
        if register:
            self.assertEqual(next(messages), "[REGISTER] OK")
            self.assertIsNone(next(messages, None))
            return client, messages
        self.assertEqual(next(messages), "[AUTH] OK")
        send_message(client, "tls-room")
        self.assertEqual(next(messages), "[ROOM] Joined room: tls-room")
        return client, messages

    def test_authenticated_chat_over_verified_tls(self):
        sender, _ = self.connect()
        _, received = self.connect()
        send_message(sender, "שלום over TLS")
        self.assertEqual(next(received), "Alice: שלום over TLS")

    def test_registration_then_login_over_verified_tls(self):
        self.connect(username="NewTLSUser", register=True)
        sender, _ = self.connect(username="NewTLSUser")
        _, received = self.connect()
        send_message(sender, "hello")
        self.assertEqual(next(received), "NewTLSUser: hello")

    def test_health_api_over_verified_tls(self):
        api_server = create_api_server(
            self.store, port=0, tls_context=self.context,
            reputation_checker=VirusTotalChecker(api_key=""),
        )
        api_thread = threading.Thread(target=api_server.serve_forever, daemon=True)
        api_thread.start()
        try:
            context = client_context("127.0.0.1", tls=True, cafile=str(self.cert))
            connection = http.client.HTTPSConnection(
                "127.0.0.1", api_server.server_port, context=context, timeout=5
            )
            connection.request("GET", "/health")
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            self.assertEqual(
                json.loads(response.read()),
                {"status": "ok", "database": "ok", "anti_bot": "not_configured"},
            )
            connection.close()
        finally:
            api_server.shutdown()
            api_server.server_close()
            api_thread.join(timeout=5)
            self.assertFalse(api_thread.is_alive())

    def test_untrusted_server_certificate_is_rejected(self):
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.connect(trusted=False)

    def test_wrong_server_identity_is_rejected(self):
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.connect(hostname="wrong.example")


if __name__ == "__main__":
    unittest.main()
