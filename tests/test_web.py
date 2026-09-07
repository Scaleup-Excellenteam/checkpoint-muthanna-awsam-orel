"""Real HTTP-to-TCP integration, with separate browser cookies."""
import argparse
import http.client
import json
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest

from chat.auth import UserStore
from chat.dlp import IMMEDIATE_BLOCK_WORD
from chat.server import handle_client
from chat.web import WebServer


class WebTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.store = UserStore(Path(self.directory.name) / "users.db")
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen()
        self.listener.settimeout(.1)
        self.stop = threading.Event()
        self.workers = []

        def accept():
            while not self.stop.is_set():
                try:
                    connection, _ = self.listener.accept()
                except socket.timeout:
                    continue
                worker = threading.Thread(target=handle_client, args=(connection, self.store), daemon=True)
                worker.start()
                self.workers.append(worker)

        self.accept_thread = threading.Thread(target=accept)
        self.accept_thread.start()
        options = argparse.Namespace(host="127.0.0.1", port=self.listener.getsockname()[1],
                                     tls=False, cafile=None, server_hostname=None)
        self.web = WebServer(("127.0.0.1", 0), options)
        self.web_thread = threading.Thread(target=self.web.serve_forever)
        self.web_thread.start()

    def tearDown(self):
        self.web.shutdown()
        self.web.server_close()
        self.web_thread.join()
        self.stop.set()
        self.accept_thread.join()
        self.listener.close()
        for worker in self.workers:
            worker.join(timeout=2)
        self.directory.cleanup()

    def request(self, path, data=None, cookie="", origin=None):
        client = http.client.HTTPConnection("127.0.0.1", self.web.server_port, timeout=5)
        headers = {"Content-Type": "application/json", "Cookie": cookie}
        if origin:
            headers["Origin"] = origin
        client.request("GET" if data is None else "POST", path,
                       None if data is None else json.dumps(data), headers)
        response = client.getresponse()
        raw = response.read()
        result = json.loads(raw) if response.getheader("Content-Type").startswith("application/json") else raw
        cookie = response.getheader("Set-Cookie", "").split(";")[0]
        status = response.status
        client.close()
        return status, result, cookie

    def login(self, username):
        credentials = {"username": username, "password": "test-only password", "room": "web-room"}
        self.assertEqual(self.request("/api/register", credentials)[0], 201)
        status, result, cookie = self.request("/api/login", credentials)
        self.assertEqual(status, 200, result)
        self.assertEqual(result["room"], "web-room")
        return cookie

    def test_chat_blocking_and_logout(self):
        alice, bob = self.login("Alice"), self.login("Bobby")
        self.assertEqual(self.request("/api/send", {"message": "hello from browser"}, alice)[0], 200)
        received = []
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline and not received:
            received.extend(self.request("/api/events", cookie=bob)[1]["messages"])
            time.sleep(.02)
        self.assertEqual(received, ["Alice: hello from browser"])
        self.assertEqual(self.request("/api/send", {"message": IMMEDIATE_BLOCK_WORD}, alice)[0], 200)
        notices = []
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            state = self.request("/api/events", cookie=alice)[1]
            notices.extend(state["messages"])
            if not state["connected"]:
                break
            time.sleep(.02)
        self.assertFalse(state["connected"])
        self.assertTrue(any(message.startswith("[SECURITY]") for message in notices))
        self.assertEqual(self.request("/api/events", cookie=bob)[1]["messages"], [])
        self.assertEqual(self.request("/api/send", {"message": "blocked user"}, alice)[0], 401)
        self.assertEqual(self.request("/api/logout", {}, bob)[0], 200)
        self.assertEqual(self.request("/api/events", cookie=bob)[0], 401)

    def test_static_assets_auth_and_origin_guards(self):
        for path in ("/", "/app.css", "/app.js", "/api/settings"):
            self.assertEqual(self.request(path)[0], 200)
        self.assertEqual(self.request("/../../config.json")[0], 404)
        self.assertEqual(self.request("/api/events")[0], 401)
        self.assertEqual(self.request("/api/send", {"message": "no login"})[0], 401)
        self.assertEqual(self.request("/api/register", {}, origin="https://example.com")[0], 403)
        self.assertEqual(self.request("/api/login", {"username": "Alice", "password": "incorrect"})[0], 400)
