"""REST API, browser UI, and authenticated web-room messaging."""

import json
import logging
import secrets
import threading
import time
from datetime import timedelta
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, unquote, urlsplit

from .auth import valid_username
from .config import LIMITS, NETWORK, STORAGE, WEB, project_path
from .dlp import PUBLIC_BLOCK_MESSAGE, find_sensitive_words, requires_immediate_block
from .protocol import MAX_AUTH_BYTES, MAX_MESSAGE_BYTES, ProtocolError, valid_room, validate_text
from .reputation import VirusTotalChecker

logger = logging.getLogger(__name__)
WEB_ROOT = project_path(STORAGE["web_directory"])
WEB_SESSION_SECONDS = timedelta(minutes=WEB["session_minutes"]).total_seconds()
MAX_WEB_JSON_BYTES = MAX_MESSAGE_BYTES + WEB["json_request_overhead_bytes"]
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/styles.css": ("styles.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
}


class ApiServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(
        self,
        address,
        user_store,
        reputation_checker,
        room_provider,
        block_callback=None,
        tcp_broadcast=None,
        clock=time.time,
    ):
        super().__init__(address, ApiHandler)
        self.user_store = user_store
        self.reputation_checker = reputation_checker
        self.room_provider = room_provider
        self.block_callback = block_callback or (lambda username: None)
        self.tcp_broadcast = tcp_broadcast or (lambda room, message: 0)
        self.clock = clock
        self.state_lock = threading.RLock()
        self.sessions = {}
        self.web_rooms = {}
        self.next_message_id = 1

    def create_session(self, username):
        token = secrets.token_urlsafe(WEB["session_token_bytes"])
        with self.state_lock:
            self._purge_expired_sessions_locked()
            self.sessions[token] = {
                "username": username,
                "expires_at": self.clock() + WEB_SESSION_SECONDS,
                "room": None,
            }
        return token

    def get_session(self, token):
        with self.state_lock:
            self._purge_expired_sessions_locked()
            session = self.sessions.get(token)
            return dict(session) if session is not None else None

    def revoke_token(self, token):
        with self.state_lock:
            self._drop_session_locked(token)

    def revoke_user(self, username):
        with self.state_lock:
            tokens = [
                token
                for token, session in self.sessions.items()
                if session["username"] == username
            ]
            for token in tokens:
                self._drop_session_locked(token)
        return len(tokens)

    def create_room(self, token, room):
        with self.state_lock:
            self._purge_expired_sessions_locked()
            known_rooms = set(self.web_rooms) | set(self.room_provider())
            if room in known_rooms:
                return False
            self.web_rooms[room] = {"sessions": set(), "messages": []}
            self._join_room_locked(token, room)
            return True

    def join_room(self, token, room):
        with self.state_lock:
            self._purge_expired_sessions_locked()
            if room not in self.web_rooms:
                if room not in set(self.room_provider()):
                    return False
                self.web_rooms[room] = {"sessions": set(), "messages": []}
            return self._join_room_locked(token, room)

    def leave_room(self, token):
        with self.state_lock:
            session = self.sessions.get(token)
            if session is None:
                return None
            previous_room = session["room"]
            if previous_room in self.web_rooms:
                self.web_rooms[previous_room]["sessions"].discard(token)
            session["room"] = None
            return previous_room

    def list_rooms(self):
        with self.state_lock:
            self._purge_expired_sessions_locked()
            names = sorted(set(self.web_rooms) | set(self.room_provider()))
            result = []
            for name in names:
                room = self.web_rooms.get(name, {"sessions": set(), "messages": []})
                members = {
                    self.sessions[token]["username"]
                    for token in room["sessions"]
                    if token in self.sessions
                }
                result.append(
                    {
                        "name": name,
                        "members": len(members),
                        "messages": len(room["messages"]),
                    }
                )
            return result

    def messages_after(self, token, room, after_id):
        with self.state_lock:
            session = self.sessions.get(token)
            if session is None or session["room"] != room or room not in self.web_rooms:
                return None
            return [
                dict(message)
                for message in self.web_rooms[room]["messages"]
                if message["id"] > after_id
            ]

    def publish_message(self, room, username, text):
        with self.state_lock:
            room_state = self.web_rooms.setdefault(
                room, {"sessions": set(), "messages": []}
            )
            message = {
                "id": self.next_message_id,
                "username": username,
                "text": text,
                "timestamp": self.clock(),
            }
            self.next_message_id += 1
            room_state["messages"].append(message)
            del room_state["messages"][:-WEB["messages_kept_per_room"]]
            recipients = {
                self.sessions[token]["username"]
                for token in room_state["sessions"]
                if token in self.sessions and self.sessions[token]["username"] != username
            }
            return len(recipients)

    def _join_room_locked(self, token, room):
        session = self.sessions.get(token)
        if session is None:
            return False
        previous_room = session["room"]
        if previous_room in self.web_rooms:
            self.web_rooms[previous_room]["sessions"].discard(token)
        self.web_rooms[room]["sessions"].add(token)
        session["room"] = room
        return True

    def _drop_session_locked(self, token):
        session = self.sessions.pop(token, None)
        if session is not None and session["room"] in self.web_rooms:
            self.web_rooms[session["room"]]["sessions"].discard(token)

    def _purge_expired_sessions_locked(self):
        now = self.clock()
        expired = [
            token
            for token, session in self.sessions.items()
            if session["expires_at"] <= now
        ]
        for token in expired:
            self._drop_session_locked(token)


class ApiHandler(BaseHTTPRequestHandler):
    server_version = NETWORK["api_server_version"]

    def send_json(self, status, data):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def send_static(self, path):
        filename, content_type = STATIC_FILES[path]
        try:
            body = (WEB_ROOT / filename).read_bytes()
        except OSError:
            self.send_json(HTTPStatus.NOT_FOUND, {"error": "Web UI is unavailable."})
            return
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'",
        )
        self.end_headers()
        self.wfile.write(body)

    def read_json(self, max_bytes=MAX_AUTH_BYTES):
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
        if size > max_bytes:
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

    def bearer_token(self):
        authorization = self.headers.get("Authorization", "")
        scheme, separator, token = authorization.partition(" ")
        if separator and scheme.lower() == "bearer" and token:
            return token
        return None

    def require_session(self):
        token = self.bearer_token()
        session = self.server.get_session(token) if token else None
        if session is None:
            self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Authentication required."})
            return None
        remaining, _ = self.server.user_store.block_status(session["username"])
        if remaining:
            self.server.revoke_user(session["username"])
            self.send_json(
                HTTPStatus.FORBIDDEN,
                {
                    "error": "Account temporarily blocked.",
                    "retry_after_seconds": remaining,
                },
            )
            return None
        return token, session

    def do_GET(self):
        parsed = urlsplit(self.path)
        path = parsed.path
        if path in STATIC_FILES:
            self.send_static(path)
            return
        if path == "/health":
            self.handle_health()
            return
        if path == "/ui-config":
            self.send_json(
                HTTPStatus.OK,
                {
                    "poll_interval_milliseconds": WEB["poll_interval_milliseconds"],
                    "message_bytes": LIMITS["message_bytes"],
                    "room_min_characters": LIMITS["room_min_characters"],
                    "room_max_characters": LIMITS["room_bytes"],
                    "username_min_characters": LIMITS["username_min_characters"],
                    "username_max_characters": LIMITS["username_max_characters"],
                    "password_min_characters": LIMITS["password_min_characters"],
                    "password_max_utf8_bytes": LIMITS["password_max_utf8_bytes"],
                },
            )
            return
        if path == "/rooms":
            authenticated = self.require_session()
            if authenticated is not None:
                self.send_json(HTTPStatus.OK, {"rooms": self.server.list_rooms()})
            return
        room, action = self.room_action(path)
        if room is not None and action == "messages":
            self.handle_get_messages(room, parsed.query)
            return
        self.send_json(HTTPStatus.NOT_FOUND, {"error": "Not found."})

    def do_POST(self):
        path = urlsplit(self.path).path
        if path in ("/register", "/login"):
            self.handle_account_endpoint(path)
            return
        if path == "/rooms" and self.bearer_token() is None:
            self.handle_legacy_room_list()
            return
        if path == "/logout":
            authenticated = self.require_session()
            if authenticated is not None:
                token, session = authenticated
                self.server.revoke_token(token)
                logger.info("event=account source=web action=logout username=%s result=success", session["username"])
                self.send_json(HTTPStatus.OK, {"message": "Logged out."})
            return
        if path == "/rooms":
            self.handle_create_room()
            return
        room, action = self.room_action(path)
        if room is not None and action == "join":
            self.handle_join_room(room)
            return
        if room is not None and action == "leave":
            self.handle_leave_room(room)
            return
        if room is not None and action == "messages":
            self.handle_post_message(room)
            return
        self.send_json(HTTPStatus.NOT_FOUND, {"error": "Not found."})

    def handle_health(self):
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

    def check_reputation(self):
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
            return False
        return True

    def handle_account_endpoint(self, path):
        if not self.check_reputation():
            return
        credentials = self.credentials()
        action = path.removeprefix("/")
        if credentials is None:
            logger.info(
                "event=account source=rest action=%s username=unknown "
                "result=failure reason=invalid_request",
                action,
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
                logger.info("event=account source=rest action=register username=%s result=failure", logged_username)
                self.send_json(status, {"error": str(error)})
                return
            logger.info("event=account source=rest action=register username=%s result=success", logged_username)
            self.send_json(HTTPStatus.CREATED, {"message": "Account created."})
            return

        authenticated, blocked_seconds = self.server.user_store.login_status(username, password)
        if blocked_seconds:
            logger.info(
                "event=account source=rest action=login username=%s "
                "result=blocked remaining_seconds=%d",
                logged_username,
                blocked_seconds,
            )
            self.send_json(
                HTTPStatus.FORBIDDEN,
                {"error": "Account temporarily blocked.", "retry_after_seconds": blocked_seconds},
            )
        elif authenticated:
            token = self.server.create_session(username)
            logger.info("event=account source=rest action=login username=%s result=success", logged_username)
            self.send_json(
                HTTPStatus.OK,
                {"message": "Authenticated.", "username": username, "token": token},
            )
        else:
            logger.info("event=account source=rest action=login username=%s result=failure", logged_username)
            self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Invalid username or password."})

    def handle_legacy_room_list(self):
        if not self.check_reputation():
            return
        credentials = self.credentials()
        if credentials is None:
            return
        username, password = credentials
        authenticated, blocked_seconds = self.server.user_store.login_status(username, password)
        if blocked_seconds:
            self.send_json(
                HTTPStatus.FORBIDDEN,
                {"error": "Account temporarily blocked.", "retry_after_seconds": blocked_seconds},
            )
        elif authenticated:
            self.send_json(HTTPStatus.OK, {"rooms": self.server.room_provider()})
        else:
            self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Invalid username or password."})

    def handle_create_room(self):
        authenticated = self.require_session()
        if authenticated is None:
            return
        token, session = authenticated
        data = self.read_json()
        room = data.get("room", "") if data is not None else ""
        if data is None:
            return
        room = room.strip() if isinstance(room, str) else room
        if set(data) != {"room"} or not valid_room(room):
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Invalid group code."})
            return
        if not self.server.create_room(token, room):
            self.send_json(HTTPStatus.CONFLICT, {"error": "Group already exists."})
            return
        logger.info("event=room_join source=web username=%s room=%s created=true", session["username"], room)
        self.send_json(HTTPStatus.CREATED, {"room": room})

    def handle_join_room(self, room):
        authenticated = self.require_session()
        if authenticated is None:
            return
        token, session = authenticated
        if not valid_room(room):
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Invalid group code."})
            return
        if not self.server.join_room(token, room):
            self.send_json(HTTPStatus.NOT_FOUND, {"error": "Group not found."})
            return
        logger.info("event=room_join source=web username=%s room=%s", session["username"], room)
        self.send_json(HTTPStatus.OK, {"room": room})

    def handle_leave_room(self, room):
        authenticated = self.require_session()
        if authenticated is None:
            return
        token, session = authenticated
        if session["room"] != room:
            self.send_json(HTTPStatus.CONFLICT, {"error": "You are not in this group."})
            return
        self.server.leave_room(token)
        logger.info("event=room_leave source=web username=%s room=%s", session["username"], room)
        self.send_json(HTTPStatus.OK, {"message": "Left group."})

    def handle_get_messages(self, room, query):
        authenticated = self.require_session()
        if authenticated is None:
            return
        token, _ = authenticated
        try:
            after_id = int(parse_qs(query).get("after", ["0"])[0])
        except ValueError:
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Invalid message cursor."})
            return
        messages = self.server.messages_after(token, room, max(after_id, 0))
        if messages is None:
            self.send_json(HTTPStatus.FORBIDDEN, {"error": "Join this group first."})
            return
        self.send_json(HTTPStatus.OK, {"messages": messages})

    def handle_post_message(self, room):
        authenticated = self.require_session()
        if authenticated is None:
            return
        token, session = authenticated
        if session["room"] != room:
            self.send_json(HTTPStatus.FORBIDDEN, {"error": "Join this group first."})
            return
        data = self.read_json(MAX_WEB_JSON_BYTES)
        if data is None:
            return
        message = data.get("message")
        if set(data) != {"message"} or not isinstance(message, str) or not message:
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": "Message cannot be empty."})
            return
        try:
            validate_text(message)
        except ProtocolError as error:
            self.send_json(HTTPStatus.BAD_REQUEST, {"error": str(error)})
            return
        message_bytes = len(message.encode("utf-8"))
        if message_bytes > MAX_MESSAGE_BYTES:
            self.send_json(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, {"error": "Message is too large."})
            return

        username = session["username"]
        matched_words = find_sensitive_words(message)
        dlp_result = self.server.user_store.record_dlp_usage(
            username,
            matched_words,
            requires_immediate_block(matched_words),
        )
        if dlp_result["blocked"]:
            logger.warning(
                "event=message source=web username=%s room=%s bytes=%d matched=%s "
                "new_words=%s before=%d after=%d limit=%d verdict=BLOCK "
                "reason=%s recipients=0",
                username,
                room,
                message_bytes,
                ",".join(sorted(matched_words)) or "none",
                ",".join(sorted(dlp_result["new_words"])) or "none",
                dlp_result["before"],
                dlp_result["after"],
                dlp_result["limit"],
                dlp_result["reason"],
            )
            self.server.revoke_user(username)
            self.server.block_callback(username)
            self.send_json(HTTPStatus.FORBIDDEN, {"error": PUBLIC_BLOCK_MESSAGE})
            return

        web_recipients = self.server.publish_message(room, username, message)
        tcp_recipients = self.server.tcp_broadcast(room, f"{username}: {message}")
        logger.info(
            "event=message source=web username=%s room=%s bytes=%d matched=%s "
            "new_words=%s before=%d after=%d limit=%d verdict=ALLOW "
            "reason=%s recipients=%d",
            username,
            room,
            message_bytes,
            ",".join(sorted(matched_words)) or "none",
            ",".join(sorted(dlp_result["new_words"])) or "none",
            dlp_result["before"],
            dlp_result["after"],
            dlp_result["limit"],
            dlp_result["reason"],
            web_recipients + tcp_recipients,
        )
        self.send_json(HTTPStatus.CREATED, {"message": "Sent."})

    @staticmethod
    def room_action(path):
        parts = path.strip("/").split("/")
        if len(parts) == 3 and parts[0] == "rooms":
            return unquote(parts[1]), parts[2]
        return None, None

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
    room_provider=None,
    block_callback=None,
    tcp_broadcast=None,
):
    reputation_checker = reputation_checker or VirusTotalChecker()
    room_provider = room_provider or (lambda: [])
    server = ApiServer(
        (host, port),
        user_store,
        reputation_checker,
        room_provider,
        block_callback,
        tcp_broadcast,
    )
    if tls_context is not None:
        server.socket = tls_context.wrap_socket(server.socket, server_side=True)
    return server
