def send_message(client_socket, message):
    """Send one UTF-8 message, ending with a newline."""
    client_socket.sendall((message + "\n").encode("utf-8"))


def read_messages(client_socket):
    """Read complete lines even when TCP splits or combines messages."""
    with client_socket.makefile("r", encoding="utf-8", newline="\n") as stream:
        for line in stream:
            if line.endswith("\n"):
                yield line[:-1]
