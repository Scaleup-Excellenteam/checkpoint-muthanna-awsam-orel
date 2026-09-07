import socket
import threading

import logging
logging.basicConfig(filename="server.log", format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

from protocol import read_messages, send_message

HOST = "10.124.38.204"
PORT = 55555

# Each connected socket belongs to one room code.
active_clients = {}
clients_lock = threading.Lock()

def broadcast_message(message, sending_client):
    """Send only to other clients in the sender's room."""
    failed_clients = []
    # Serialize writes so messages from different threads cannot overlap.
    with clients_lock:
        room = active_clients.get(sending_client)
        if room is None:
            return
        for client, client_room in active_clients.items():
            if client != sending_client and client_room == room:
                try:
                    logger.info(f"Broadcasting message to {client.getpeername()}: {message}")
                    send_message(client, message)
                except OSError:
                    failed_clients.append(client)

    for client in failed_clients:
        remove_client(client)

def handle_client(client_socket):
    """The first line selects a room; the remaining lines are chat messages."""
    try:
        messages = read_messages(client_socket)
        room = next(messages, "").strip()
        if not room:
            send_message(client_socket, "[ERROR] Room code cannot be empty.")
            return

        with clients_lock:
            send_message(client_socket, f"[ROOM] Joined room: {room}")
            active_clients[client_socket] = room

        for message in messages:
            broadcast_message(message, client_socket)
    except (OSError, UnicodeError):
        pass
    finally:
        remove_client(client_socket)

def remove_client(client_socket):
    """Remove membership; rooms disappear when their last client leaves."""
    with clients_lock:
        active_clients.pop(client_socket, None)
    try:
        client_socket.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    client_socket.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen()
    print(f"[STARTING] Server is listening on {HOST}:{PORT}...")

    while True:
        # Accept a new client connection
        client_socket, client_address = server.accept()
        print(f"[NEW CONNECTION] Connected with {client_address}")

        # Start a new thread dedicated to handling this specific client
        thread = threading.Thread(target=handle_client, args=(client_socket,))
        thread.start()


if __name__ == "__main__":
    start_server()
