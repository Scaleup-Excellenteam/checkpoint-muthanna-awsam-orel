import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path

from chat.api import create_api_server
from chat.auth import UserStore
from chat.dlp import IMMEDIATE_BLOCK_WORD
from chat.reputation import ReputationDecision


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.store = UserStore(Path(self.directory.name) / "users.db")
        self.server = create_api_server(self.store, port=0)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server)

    def stop_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

    def request(self, method, path, data=None, headers=None):
        body = None if data is None else json.dumps(data)
        request_headers = headers or {}
        if data is not None and "Content-Type" not in request_headers:
            request_headers["Content-Type"] = "application/json"
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=2)
        connection.request(method, path, body=body, headers=request_headers)
        response = connection.getresponse()
        result = response.status, response.getheader("Content-Type"), json.loads(response.read())
        connection.close()
        return result

    def test_health(self):
        status, content_type, body = self.request("GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(content_type, "application/json; charset=utf-8")
        self.assertEqual(
            body,
            {"status": "ok", "database": "ok", "anti_bot": "not_configured"},
        )

    def test_register_then_login(self):
        credentials = {"username": "ApiUser", "password": "a strong API password"}
        self.assertEqual(self.request("POST", "/register", credentials)[0], 201)
        status, _, body = self.request("POST", "/login", credentials)
        self.assertEqual(status, 200)
        self.assertEqual(body, {"message": "Authenticated.", "username": "ApiUser"})

    def test_duplicate_registration_and_bad_login(self):
        credentials = {"username": "ApiUser", "password": "a strong API password"}
        self.request("POST", "/register", credentials)
        self.assertEqual(self.request("POST", "/register", credentials)[0], 409)
        credentials["password"] = "a different password"
        status, _, body = self.request("POST", "/login", credentials)
        self.assertEqual(status, 401)
        self.assertEqual(body, {"error": "Invalid username or password."})

    def test_validation_and_unknown_route(self):
        self.assertEqual(self.request("POST", "/register", {"username": "x"})[0], 400)
        self.assertEqual(self.request("POST", "/register", [], {"Content-Type": "text/plain"})[0], 415)
        self.assertEqual(self.request("GET", "/missing")[0], 404)

    def test_large_body_is_rejected(self):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=2)
        connection.request(
            "POST",
            "/register",
            body=b"x" * 2049,
            headers={"Content-Type": "application/json", "Content-Length": "2049"},
        )
        response = connection.getresponse()
        self.assertEqual(response.status, 413)
        response.read()
        connection.close()

    def test_blocked_account_cannot_login_through_rest(self):
        credentials = {"username": "BlockedApi", "password": "a strong API password"}
        self.assertEqual(self.request("POST", "/register", credentials)[0], 201)
        self.store.record_dlp_usage(
            credentials["username"], {IMMEDIATE_BLOCK_WORD}, immediate_block=True
        )
        status, _, body = self.request("POST", "/login", credentials)
        self.assertEqual(status, 403)
        self.assertEqual(body["error"], "Account temporarily blocked.")
        self.assertGreater(body["retry_after_seconds"], 0)
        self.assertNotIn(IMMEDIATE_BLOCK_WORD, json.dumps(body))

    def test_reputation_block_applies_to_auth_routes_but_not_health(self):
        class BlockingChecker:
            status = "configured"

            def __init__(self):
                self.calls = []

            def check(self, address):
                self.calls.append(address)
                return ReputationDecision("BLOCK", "malicious reputation", malicious=1)

        checker = BlockingChecker()
        self.server.reputation_checker = checker
        self.assertEqual(self.request("GET", "/health")[0], 200)
        self.assertEqual(checker.calls, [])
        status, _, body = self.request(
            "POST",
            "/register",
            {"username": "NeverCreated", "password": "a strong API password"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(
            body, {"verdict": "BLOCK", "reason": "malicious reputation"}
        )
        self.assertEqual(checker.calls, ["127.0.0.1"])


if __name__ == "__main__":
    unittest.main()
