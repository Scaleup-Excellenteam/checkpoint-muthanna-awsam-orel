import socket
import threading
import secrets

from protocol import read_messages, send_message

HOST = "10.124.38.204"
PORT = 55555


def receive_messages(client_socket):
    """Receive messages while the main thread waits for keyboard input."""
    try:
        for message in read_messages(client_socket):
            print(message)
    except (OSError, UnicodeError):
        pass
    finally:
        print("\n[DISCONNECTED] Disconnected from server.")


def start_client():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        username = input("Enter your username: ").strip() or "Guest"
        room = input("Room code (Enter to create a new room): ").strip()
        if not room:
            room = secrets.token_urlsafe(12)

        client_socket.connect((HOST, PORT))
        send_message(client_socket, room)
        receive_thread = threading.Thread(
            target=receive_messages,
            args=(client_socket,),
            daemon=True,
        )
        receive_thread.start()

        while True:
            text = input()
            if text.lower() == "exit":
                break

            message = f"{username}: {text}"
            send_message(client_socket, message)
    except OSError:
        print("[ERROR] Could not connect or send a message.")
    except (EOFError, KeyboardInterrupt):
        print("\n[EXIT] Closing the client.")
    finally:
        # Stop both sending and receiving before closing the socket.
        try:
            client_socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            # A failed connection may already be disconnected.
            pass
        client_socket.close()


if __name__ == "__main__":
    start_client()
