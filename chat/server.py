import argparse
import json
import logging
import re
import socket
import sqlite3
import threading
from pathlib import Path

from .auth import DEFAULT_USERS_DB, UserStore, valid_username
from .api import create_api_server
from .config import LIMITS, NETWORK
from .dlp import (
    BLOCK_SECONDS,
    PUBLIC_BLOCK_MESSAGE,
    find_sensitive_words,
    requires_immediate_block,
)
from .protocol import (
    MAX_AUTH_BYTES, MAX_MESSAGE_BYTES, MAX_ROOM_BYTES,
    ProtocolError, read_message, send_message,
)
from .transport import server_context
from .reputation import VirusTotalChecker

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

HOST = NETWORK["host"]
PORT = NETWORK["chat_port"]
API_PORT = NETWORK["api_port"]
HANDSHAKE_TIMEOUT = NETWORK["handshake_timeout_seconds"]
ROOM_PATTERN = re.compile(
    rf"[A-Za-z0-9_-]{{{LIMITS['room_min_characters']},{LIMITS['room_bytes']}}}\Z"
)

# Each connected socket belongs to one room code.
active_clients = {}
clients_lock = threading.Lock()

def client_ip(client_socket):
    try:
        return client_socket.getpeername()[0]
    except OSError:
        return "unknown"


def broadcast_message(message, sending_client):
    """Send only to other clients in the sender's room."""
    failed_clients = []
    recipients = 0
    # Serialize writes so messages from different threads cannot overlap.
    with clients_lock:
        session = active_clients.get(sending_client)
        if session is None:
            return 0
        room = session["room"]
        for client, client_session in active_clients.items():
            if client != sending_client and client_session["room"] == room:
                try:
                    send_message(client, message)
                    recipients += 1
                except OSError:
                    failed_clients.append(client)

    for client in failed_clients:
        remove_client(client)
    return recipients


def check_client_reputation(client_socket, reputation_checker):
    address = client_ip(client_socket)
    decision = reputation_checker.check(address)
    logger.info(
        "event=anti_bot ip=%s verdict=%s malicious=%d suspicious=%d reputation=%d reason=%s",
        address,
        decision.verdict,
        decision.malicious,
        decision.suspicious,
        decision.reputation,
        decision.reason,
    )
    send_message(client_socket, decision.client_message())
    return decision.allowed


def handle_account(client_socket, stream, user_store):
    """Step 1: register an account or log in before accessing any room."""
    request = read_message(stream, MAX_AUTH_BYTES)
    username, response = user_store.handle_request(request)
    send_message(client_socket, response)
    try:
        request_data = json.loads(request) if request else {}
        requested_username = request_data.get("username", "unknown")
        action = request_data.get("action", "login")
    except (ValueError, AttributeError):
        requested_username = "unknown"
        action = "invalid"
    if not valid_username(requested_username):
        requested_username = "invalid"
    if action not in ("register", "login"):
        action = "invalid"
    result = "success" if response in ("[REGISTER] OK", "[AUTH] OK") else "failure"
    logger.info(
        "event=account action=%s username=%s result=%s",
        action,
        requested_username,
        result,
    )
    return username


def join_room(client_socket, stream, username):
    """Step 2: validate the room code and register the connection."""
    room = read_message(stream, MAX_ROOM_BYTES)
    if room is None or not room.strip():
        send_message(client_socket, "[ERROR] Room code cannot be empty.")
        return False
    room = room.strip()
    if not ROOM_PATTERN.fullmatch(room):
        send_message(client_socket, "[ERROR] Room code must contain letters, digits, '_' or '-'.")
        return False
    with clients_lock:
        send_message(client_socket, f"[ROOM] Joined room: {room}")
        active_clients[client_socket] = {"room": room, "username": username}
    logger.info("event=room_join username=%s room=%s", username, room)
    return True


def disconnect_account(username):
    """Notify and disconnect every active session belonging to an account."""
    with clients_lock:
        sockets = [
            client
            for client, session in active_clients.items()
            if session["username"] == username
        ]
    for client in sockets:
        try:
            send_message(client, PUBLIC_BLOCK_MESSAGE)
        except OSError:
            pass
        remove_client(client)


def handle_client(client_socket, user_store, tls_context=None, reputation_checker=None):
    """Authenticate first, select a room, then accept bounded chat messages."""
    try:
        reputation_checker = reputation_checker or VirusTotalChecker()
        address = client_ip(client_socket)
        logger.info("event=connection_open ip=%s", address)
        client_socket.settimeout(HANDSHAKE_TIMEOUT)
        if tls_context is not None:
            client_socket = tls_context.wrap_socket(client_socket, server_side=True)
        if not check_client_reputation(client_socket, reputation_checker):
            logger.warning("event=connection_blocked ip=%s", address)
            return
        with client_socket.makefile("rb") as stream:
            username = handle_account(client_socket, stream, user_store)
            if username is None:
                return
            if not join_room(client_socket, stream, username):
                return
            client_socket.settimeout(None)
            logger.info("User %s joined a room", username)

            # Step 3: the server labels each message with the verified username.
            while True:
                message = read_message(stream, MAX_MESSAGE_BYTES)
                if message is None:
                    break
                matched_words = find_sensitive_words(message)
                dlp_result = user_store.record_dlp_usage(
                    username,
                    matched_words,
                    requires_immediate_block(matched_words),
                )
                with clients_lock:
                    session = active_clients.get(client_socket)
                    room = session["room"] if session else "unknown"
                if dlp_result["blocked"]:
                    logger.warning(
                        "event=message username=%s room=%s bytes=%d matched=%s "
                        "new_words=%s before=%d after=%d limit=%d verdict=BLOCK "
                        "reason=%s recipients=0",
                        username,
                        room,
                        len(message.encode("utf-8")),
                        ",".join(sorted(matched_words)) or "none",
                        ",".join(sorted(dlp_result["new_words"])) or "none",
                        dlp_result["before"],
                        dlp_result["after"],
                        dlp_result["limit"],
                        dlp_result["reason"],
                    )
                    logger.warning(
                        "event=account_blocked username=%s block_started=%.3f "
                        "block_ends=%.3f duration_seconds=%.3f trigger=%s matched=%s",
                        username,
                        dlp_result["blocked_until"] - BLOCK_SECONDS,
                        dlp_result["blocked_until"],
                        BLOCK_SECONDS,
                        dlp_result["reason"],
                        ",".join(sorted(matched_words)) or "none",
                    )
                    disconnect_account(username)
                    return
                recipients = broadcast_message(f"{username}: {message}", client_socket)
                logger.info(
                    "event=message username=%s room=%s bytes=%d matched=%s "
                    "new_words=%s before=%d after=%d limit=%d verdict=ALLOW "
                    "reason=%s recipients=%d",
                    username,
                    room,
                    len(message.encode("utf-8")),
                    ",".join(sorted(matched_words)) or "none",
                    ",".join(sorted(dlp_result["new_words"])) or "none",
                    dlp_result["before"],
                    dlp_result["after"],
                    dlp_result["limit"],
                    dlp_result["reason"],
                    recipients,
                )
    except (ProtocolError, UnicodeError):
        logger.warning("Invalid or oversized message")
        try:
            send_message(client_socket, "[ERROR] Invalid or oversized message.")
        except OSError:
            pass
    except (OSError, sqlite3.Error) as error:
        # Never log received authentication data or exception payloads containing it.
        logger.warning("Connection closed (%s)", type(error).__name__)
    finally:
        remove_client(client_socket)

def remove_client(client_socket):
    """Remove membership; rooms disappear when their last client leaves."""
    address = client_ip(client_socket)
    with clients_lock:
        session = active_clients.pop(client_socket, None)
    if session is not None:
        logger.info(
            "event=room_leave username=%s room=%s",
            session["username"],
            session["room"],
        )
    try:
        client_socket.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    client_socket.close()
    logger.info("event=connection_close ip=%s", address)

def start_server(
    host=HOST,
    port=PORT,
    api_port=API_PORT,
    users_db=DEFAULT_USERS_DB,
    certfile=None,
    keyfile=None,
):
    tls_context = server_context(host, certfile, keyfile)
    user_store = UserStore(users_db)
    reputation_checker = VirusTotalChecker()
    logging.basicConfig(
        filename=Path(users_db).resolve().parent / "server.log",
        format="%(asctime)s - %(levelname)s - %(message)s",
        level=logging.INFO,
    )
    api_server = create_api_server(
        user_store, host, api_port, tls_context, reputation_checker
    )
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen()
    except Exception:
        api_server.server_close()
        server.close()
        raise

    api_thread = threading.Thread(target=api_server.serve_forever, daemon=True)
    api_thread.start()
    logger.info("Server started on %s:%d", host, port)
    scheme = "https" if tls_context is not None else "http"
    print(f"[STARTING] Chat: {host}:{port}")
    print(f"[STARTING] REST API: {scheme}://{host}:{api_server.server_port}")

    try:
        while True:
            client_socket, client_address = server.accept()
            logger.info("Accepted connection from %s", client_address)
            print(f"[NEW CONNECTION] Connected with {client_address}")
            thread = threading.Thread(
                target=handle_client,
                args=(client_socket, user_store, tls_context, reputation_checker),
                daemon=True,
            )
            thread.start()
    finally:
        api_server.shutdown()
        api_server.server_close()
        server.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TCP chat server with a REST API.")
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--api-port", type=int, default=API_PORT)
    parser.add_argument("--users-db", default=DEFAULT_USERS_DB)
    parser.add_argument("--cert", help="TLS server certificate (PEM)")
    parser.add_argument("--key", help="TLS private key (PEM)")
    args = parser.parse_args()
    try:
        start_server(args.host, args.port, args.api_port, args.users_db, args.cert, args.key)
    except (ValueError, OSError, sqlite3.Error) as error:
        parser.error(str(error))
