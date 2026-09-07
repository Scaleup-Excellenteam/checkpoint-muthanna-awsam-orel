"""Read successive server replies in socket integration tests."""

from chat.protocol import MAX_SERVER_MESSAGE_BYTES, read_message


def read_messages(client_socket):
    with client_socket.makefile("rb") as stream:
        while True:
            message = read_message(stream, MAX_SERVER_MESSAGE_BYTES)
            if message is None:
                return
            yield message
