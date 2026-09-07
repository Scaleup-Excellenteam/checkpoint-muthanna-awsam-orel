"""Small REST API for health checks, registration and login."""

import json
import logging
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from .auth import valid_username
from .config import NETWORK
from .protocol import MAX_AUTH_BYTES
from .reputation import VirusTotalChecker

logger = logging.getLogger(__name__)


class ApiServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, user_store, reputation_checker):
        super().__init__(address, ApiHandler)
        self.user_store = user_store
        self.reputation_checker = reputation_checker


class ApiHandler(BaseHTTPRequestHandler):
    server_version = NETWORK["api_server_version"]

    def send_json(self, status, data):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def read_json(self):
        content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower()
        if content_type != "application/json":
            self.send_json(
                HTTPStatus.UNSUPPORTED_MEDIA_TYPE,
                {"error": "Content-Type must be application/json."},
            )
            return None

        try:
            size = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Invalid Content-Length."})
            return None
        if size < 0:
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Invalid Content-Length."})
            return None
        if size > MAX_AUTH_BYTES:
            self.send_json(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                {"error": "Request body is too large."},
            )
            return None

        try:
            data = json.loads(self.rfile.read(size).decode("utf-8"))
        except (UnicodeError, ValueError, RecursionError):
            self.send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "Request body must be valid JSON."},
            )
            return None
        if not isinstance(data, dict):
            self.send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "JSON body must be an object."},
            )
            return None
        return data

    def credentials(self):
        data = self.read_json()
        if data is None:
            return None
        if set(data) != {"username", "password"}:
            self.send_json(
                HTTPStatus.BAD_REQUEST,
                {"error": "Provide username and password."},
            )
            return None
        return data["username"], data["password"]

    def do_GET(self):
        if urlsplit(self.path).path == "/health":
            try:
                self.server.user_store.check_health()
            except Exception:
                logger.exception("Health check failed")
                self.send_json(HTTPStatus.SERVICE_UNAVAILABLE, {"status": "unavailable"})
                return
            self.send_json(
                HTTPStatus.OK,
                {
                    "status": "ok",
                    "database": "ok",
                    "anti_bot": self.server.reputation_checker.status,
                },
            )
            return
        self.send_json(HTTPStatus.NOT_FOUND, {"error": "Not found."})

    def do_POST(self):
        path = urlsplit(self.path).path
        if path not in ("/register", "/login"):
            self.send_json(HTTPStatus.NOT_FOUND, {"error": "Not found."})
            return

        decision = self.server.reputation_checker.check(self.client_address[0])
        logger.info(
            "event=anti_bot source=rest ip=%s verdict=%s malicious=%d "
            "suspicious=%d reputation=%d reason=%s",
            self.client_address[0],
            decision.verdict,
            decision.malicious,
            decision.suspicious,
            decision.reputation,
            decision.reason,
        )
        if not decision.allowed:
            self.send_json(
                HTTPStatus.FORBIDDEN,
                {"verdict": decision.verdict, "reason": decision.reason},
            )
            return

        credentials = self.credentials()
        if credentials is None:
            logger.info(
                "event=account source=rest action=%s username=unknown "
                "result=failure reason=invalid_request",
                path.removeprefix("/"),
            )
            return
        username, password = credentials
        logged_username = username if valid_username(username) else "invalid"

        if path == "/register":
            try:
                self.server.user_store.create_user(username, password)
            except ValueError as error:
                status = (
                    HTTPStatus.CONFLICT
                    if str(error) == "Username already exists."
                    else HTTPStatus.BAD_REQUEST
                )
                logger.info(
                    "event=account source=rest action=register username=%s result=failure",
                    logged_username,
                )
                self.send_json(status, {"error": str(error)})
                return
            logger.info(
                "event=account source=rest action=register username=%s result=success",
                logged_username,
            )
            self.send_json(HTTPStatus.CREATED, {"message": "Account created."})
            return

        authenticated, blocked_seconds = self.server.user_store.login_status(
            username, password
        )
        if blocked_seconds:
            logger.info(
                "event=account source=rest action=login username=%s "
                "result=blocked remaining_seconds=%d",
                logged_username,
                blocked_seconds,
            )
            self.send_json(
                HTTPStatus.FORBIDDEN,
                {
                    "error": "Account temporarily blocked.",
                    "retry_after_seconds": blocked_seconds,
                },
            )
        elif authenticated:
            logger.info(
                "event=account source=rest action=login username=%s result=success",
                logged_username,
            )
            self.send_json(
                HTTPStatus.OK,
                {"message": "Authenticated.", "username": username},
            )
        else:
            logger.info(
                "event=account source=rest action=login username=%s result=failure",
                logged_username,
            )
            self.send_json(
                HTTPStatus.UNAUTHORIZED,
                {"error": "Invalid username or password."},
            )

    def log_request(self, code="-", size="-"):
        logger.info(
            "event=rest_request ip=%s method=%s path=%s status=%s",
            self.client_address[0],
            self.command,
            urlsplit(self.path).path,
            code,
        )

    def log_error(self, message, *args):
        logger.warning("event=rest_server_error ip=%s", self.client_address[0])


def create_api_server(
    user_store,
    host=NETWORK["host"],
    port=NETWORK["api_port"],
    tls_context=None,
    reputation_checker=None,
):
    reputation_checker = reputation_checker or VirusTotalChecker()
    server = ApiServer((host, port), user_store, reputation_checker)
    if tls_context is not None:
        server.socket = tls_context.wrap_socket(server.socket, server_side=True)
    return server
