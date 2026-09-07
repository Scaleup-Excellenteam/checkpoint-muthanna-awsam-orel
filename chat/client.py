import argparse
import getpass
import json
import secrets
import socket
import threading

from .protocol import (
    MAX_AUTH_BYTES, MAX_MESSAGE_BYTES, MAX_ROOM_BYTES, MAX_SERVER_MESSAGE_BYTES,
    ProtocolError, read_message, send_message,
)
from .transport import client_context

HOST = "127.0.0.1"
PORT = 55555


def receive_messages(stream):
    """Receive messages while the main thread waits for keyboard input."""
    try:
        while True:
            message = read_message(stream, MAX_SERVER_MESSAGE_BYTES)
            if message is None:
                break
            print(message)
    except (OSError, UnicodeError, ProtocolError):
        pass
    finally:
        print("\n[DISCONNECTED] Disconnected from server.")


def account_request(client_socket, stream, action, username, password):
    """Use the same small request format for registration and login."""
    credentials = json.dumps({"action": action, "username": username, "password": password})
    send_message(client_socket, credentials, MAX_AUTH_BYTES)
    return read_message(stream, MAX_SERVER_MESSAGE_BYTES)


def join_chat(client_socket, stream, username, password, room):
    """Log in with a registered account, then join the chosen room."""
    response = account_request(client_socket, stream, "login", username, password)
    if response != "[AUTH] OK":
        print(response or "[ERROR] Server disconnected during authentication.")
        return False

    send_message(client_socket, room, MAX_ROOM_BYTES)
    response = read_message(stream, MAX_SERVER_MESSAGE_BYTES)
    print(response or "[ERROR] Server disconnected during room selection.")
    return response == f"[ROOM] Joined room: {room}"


def send_messages(client_socket):
    """Read keyboard input until exit; let the user correct oversized messages."""
    while True:
        text = input()
        if text.lower() == "exit":
            return
        try:
            send_message(client_socket, text, MAX_MESSAGE_BYTES)
        except ProtocolError as error:
            print(f"[ERROR] {error}")


def run_session(action, host, port, tls_context, server_hostname):
    """One connection handles either registration or a logged-in chat session."""
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    stream = None
    receive_thread = None

    try:
        if action == "register":
            print("Username: 3-32 letters/digits/_/-. Password: at least 8 characters, up to 256 UTF-8 bytes.")
        username = input("Enter your username: ").strip()
        password = getpass.getpass("Password: ")
        if action == "register":
            if password != getpass.getpass("Confirm password: "):
                print("[ERROR] Passwords do not match.")
                return
        else:
            room = input("Room code (Enter to create a new room): ").strip()
            if not room:
                room = secrets.token_urlsafe(12)

        client_socket.settimeout(10)
        client_socket.connect((host, port))
        if tls_context is not None:
            client_socket = tls_context.wrap_socket(client_socket, server_hostname=server_hostname or host)
        stream = client_socket.makefile("rb")
        anti_bot_message = read_message(stream, MAX_SERVER_MESSAGE_BYTES)
        if anti_bot_message is None:
            print("[ERROR] Server disconnected during the reputation check.")
            return
        print(anti_bot_message)
        if anti_bot_message.startswith("[ANTI-BOT] BLOCK:"):
            return
        if action == "register":
            response = account_request(client_socket, stream, action, username, password)
            if response == "[REGISTER] OK":
                print("Account created. Choose Login and enter your new username and password.")
            else:
                print(response or "[ERROR] Server disconnected during registration.")
            return
        joined = join_chat(client_socket, stream, username, password, room)
        del password
        if not joined:
            return
        client_socket.settimeout(None)
        receive_thread = threading.Thread(
            target=receive_messages,
            args=(stream,),
            daemon=True,
        )
        receive_thread.start()

        send_messages(client_socket)
    except (OSError, UnicodeError, ProtocolError) as error:
        print(f"[ERROR] Could not connect or exchange messages ({type(error).__name__}).")
    finally:
        # Stop both sending and receiving before closing the socket.
        try:
            client_socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            # A failed connection may already be disconnected.
            pass
        if receive_thread is not None:
            receive_thread.join(timeout=2)
        if stream is not None:
            stream.close()
        client_socket.close()


def start_client(host=HOST, port=PORT, tls=False, cafile=None, server_hostname=None):
    tls_context = client_context(host, tls, cafile)
    try:
        while True:
            print("\n1. Register\n2. Login\n3. Exit")
            choice = input("Choose an option: ").strip()
            if choice == "3":
                return
            if choice not in ("1", "2"):
                print("Please choose 1, 2 or 3.")
                continue
            action = "register" if choice == "1" else "login"
            run_session(action, host, port, tls_context, server_hostname)
    except (EOFError, KeyboardInterrupt):
        print("\n[EXIT] Closing the client.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Authenticated TCP room chat client.")
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--tls", action="store_true")
    parser.add_argument("--cafile", help="Trusted CA or self-signed server certificate (PEM)")
    parser.add_argument("--server-hostname", help="Expected name in the server certificate (defaults to --host)")
    args = parser.parse_args()
    try:
        start_client(args.host, args.port, args.tls, args.cafile, args.server_hostname)
    except (ValueError, OSError) as error:
        parser.error(str(error))
