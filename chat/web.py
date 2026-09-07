"""Local browser UI bridged to the existing authenticated TCP chat server."""
import argparse
from collections import deque
from http.cookies import SimpleCookie, CookieError
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import secrets
import socket
import threading
import time
from urllib.parse import urlsplit

from .client import account_request
from .config import NETWORK, LIMITS
from .protocol import MAX_MESSAGE_BYTES, MAX_ROOM_BYTES, MAX_SERVER_MESSAGE_BYTES, read_message, send_message
from .transport import client_context

ASSETS = Path(__file__).with_name("web_assets")


class Session:
    def __init__(self, connection, stream, username, room, verdict):
        self.connection, self.stream = connection, stream
        self.username, self.room, self.verdict = username, room, verdict
        self.messages = deque()
        self.lock = threading.Lock()
        self.send_lock = threading.Lock()
        self.connected = True
        self.last_seen = time.monotonic()

    def receive(self):
        try:
            while self.connected:
                message = read_message(self.stream, MAX_SERVER_MESSAGE_BYTES)
                if message is None:
                    break
                with self.lock:
                    if len(self.messages) >= 256:
                        self.messages.append("[ERROR] Browser fell behind. Please reconnect.")
                        break
                    self.messages.append(message)
        except (OSError, ValueError):
            pass
        finally:
            self.close()
            self.stream.close()

    def close(self):
        self.connected = False
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.connection.close()


class WebServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, options):
        self.options = options
        self.sessions = {}
        self.sessions_lock = threading.Lock()
        self.stopping = threading.Event()
        super().__init__(address, WebHandler)
        threading.Thread(target=self.cleanup, daemon=True).start()

    def cleanup(self):
        while not self.stopping.wait(30):
            with self.sessions_lock:
                expired = [token for token, session in self.sessions.items()
                           if time.monotonic() - session.last_seen > 120]
                for token in expired:
                    self.sessions.pop(token).close()

    def server_close(self):
        self.stopping.set()
        with self.sessions_lock:
            for session in self.sessions.values():
                session.close()
            self.sessions.clear()
        super().server_close()


class WebHandler(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass  # Never log credentials, cookies, or chat bodies.

    def reply(self, status, data, cookie=None, content_type="application/json; charset=utf-8"):
        body = data if isinstance(data, bytes) else json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def local_request(self):
        allowed = {f"127.0.0.1:{self.server.server_port}", f"localhost:{self.server.server_port}"}
        host = self.headers.get("Host", "")
        origin = self.headers.get("Origin")
        if host not in allowed or (origin and origin != f"http://{host}"):
            self.reply(403, {"error": "Open this app from its local address."})
            return False
        return True

    def get_session(self):
        cookie = SimpleCookie()
        try:
            cookie.load(self.headers.get("Cookie", ""))
            token = cookie["slice_session"].value
        except (KeyError, ValueError, CookieError):
            return None, None
        with self.server.sessions_lock:
            session = self.server.sessions.get(token)
            if session:
                session.last_seen = time.monotonic()
        return token, session

    def do_GET(self):
        if not self.local_request():
            return
        path = urlsplit(self.path).path
        assets = {"/": ("index.html", "text/html; charset=utf-8"),
                  "/app.css": ("app.css", "text/css; charset=utf-8"),
                  "/app.js": ("app.js", "text/javascript; charset=utf-8")}
        if path in assets:
            name, mime = assets[path]
            self.reply(200, (ASSETS / name).read_bytes(), content_type=mime)
        elif path == "/api/settings":
            self.reply(200, {"messageLimit": MAX_MESSAGE_BYTES,
                             "passwordMin": LIMITS["password_min_characters"],
                             "tls": self.server.options.tls})
        elif path == "/api/events":
            _, session = self.get_session()
            if not session:
                self.reply(401, {"error": "Sign in to join a room."})
                return
            with session.lock:
                messages = list(session.messages)
                session.messages.clear()
            self.reply(200, {"username": session.username, "room": session.room,
                             "verdict": session.verdict, "connected": session.connected,
                             "messages": messages})
        else:
            self.reply(404, {"error": "Not found."})

    def do_POST(self):
        if not self.local_request():
            return
        if self.headers.get("Content-Type", "").split(";")[0] != "application/json":
            self.reply(415, {"error": "Use a JSON request."})
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= MAX_MESSAGE_BYTES * 6 + 4096:
                raise ValueError("Request is too large or empty.")
            self.connection.settimeout(10)
            data = json.loads(self.rfile.read(size))
            if not isinstance(data, dict):
                raise ValueError("Expected a JSON object.")
            self.handle_action(urlsplit(self.path).path, data)
        except (ValueError, TypeError, KeyError) as error:
            self.reply(400, {"error": str(error)})
        except OSError:
            self.reply(503, {"error": "Cannot reach the chat server. Start it, then try again."})

    def handle_action(self, path, data):
        token, session = self.get_session()
        if path == "/api/logout":
            with self.server.sessions_lock:
                old = self.server.sessions.pop(token, None)
            if old:
                old.close()
            self.reply(200, {"ok": True}, "slice_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0")
        elif path == "/api/send":
            if not session or not session.connected:
                self.reply(401, {"error": "Connection closed. Sign in again."})
                return
            message = data.get("message")
            if not isinstance(message, str) or not message.strip():
                raise ValueError("Write a message first.")
            with session.send_lock:
                send_message(session.connection, message, MAX_MESSAGE_BYTES)
            self.reply(200, {"submitted": True})
        elif path in ("/api/login", "/api/register"):
            if session and session.connected:
                raise ValueError("Sign out before starting another session.")
            self.authenticate(path, data, token)
        else:
            self.reply(404, {"error": "Not found."})

    def authenticate(self, path, data, old_token):
        username, password = data.get("username"), data.get("password")
        room = data.get("room", "")
        if not all(isinstance(value, str) for value in (username, password, room)):
            raise ValueError("Username, password, and room must be text.")
        options = self.server.options
        context = client_context(options.host, options.tls, options.cafile)
        connection = socket.create_connection((options.host, options.port), timeout=NETWORK["handshake_timeout_seconds"])
        stream, retained = None, False
        try:
            if context:
                connection = context.wrap_socket(connection, server_hostname=options.server_hostname or options.host)
            stream = connection.makefile("rb")
            verdict = read_message(stream, MAX_SERVER_MESSAGE_BYTES)
            if not verdict or verdict.startswith("[ANTI-BOT] BLOCK:"):
                raise ValueError(verdict or "Server disconnected.")
            action = "register" if path.endswith("register") else "login"
            response = account_request(connection, stream, action, username, password)
            if response != ("[REGISTER] OK" if action == "register" else "[AUTH] OK"):
                raise ValueError(response or "Server disconnected.")
            if action == "register":
                self.reply(201, {"message": "Account created. You can sign in now."})
                return
            room = room.strip() or secrets.token_urlsafe(NETWORK["generated_room_token_bytes"])
            send_message(connection, room, MAX_ROOM_BYTES)
            response = read_message(stream, MAX_SERVER_MESSAGE_BYTES)
            if response != f"[ROOM] Joined room: {room}":
                raise ValueError(response or "Could not join room.")
            connection.settimeout(None)
            session = Session(connection, stream, username, room, verdict)
            token = secrets.token_urlsafe(32)
            with self.server.sessions_lock:
                if len(self.server.sessions) >= 100:
                    raise ValueError("Too many browser sessions. Try again later.")
                old = self.server.sessions.pop(old_token, None)
                if old:
                    old.close()
                self.server.sessions[token] = session
            retained = True
            threading.Thread(target=session.receive, daemon=True).start()
            self.reply(200, {"username": username, "room": room, "verdict": verdict},
                       f"slice_session={token}; HttpOnly; SameSite=Strict; Path=/")
        finally:
            if not retained:
                if stream:
                    stream.close()
                connection.close()


def main():
    parser = argparse.ArgumentParser(description="Local web interface for the TCP chat server")
    parser.add_argument("--web-port", type=int, default=8765)
    parser.add_argument("--host", default=NETWORK["host"], help="Chat server address")
    parser.add_argument("--port", type=int, default=NETWORK["chat_port"])
    parser.add_argument("--tls", action="store_true")
    parser.add_argument("--cafile")
    parser.add_argument("--server-hostname")
    options = parser.parse_args()
    server = WebServer(("127.0.0.1", options.web_port), options)
    print(f"Web UI: http://127.0.0.1:{server.server_port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
