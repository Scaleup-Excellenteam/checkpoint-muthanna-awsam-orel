"""Desktop flow test using a real TCP server and temporary account database."""
import argparse
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
import tkinter as tk

from chat.gui import ChatApp
from chat.auth import UserStore
from chat.server import handle_client
from chat.dlp import IMMEDIATE_BLOCK_WORD


class GuiTests(unittest.TestCase):
    def test_registration_chat_and_security_disconnect(self):
        try:
            root = tk.Tk()
        except tk.TclError:
            self.skipTest("Desktop display is unavailable")
        root.withdraw()
        directory = tempfile.TemporaryDirectory()
        store = UserStore(Path(directory.name) / "users.db")
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        listener.settimeout(0.1)
        stop = threading.Event()
        handlers = []

        def accept():
            while not stop.is_set():
                try:
                    client, _ = listener.accept()
                except socket.timeout:
                    continue
                worker = threading.Thread(target=handle_client, args=(client, store), daemon=True)
                handlers.append(worker)
                worker.start()

        accept_thread = threading.Thread(target=accept)
        accept_thread.start()
        options = argparse.Namespace(host="127.0.0.1", port=listener.getsockname()[1],
                                     tls=False, cafile=None, server_hostname=None)
        first = ChatApp(root, options)
        second_root = tk.Tk()
        second_root.withdraw()
        second = ChatApp(second_root, options)

        def wait_for(predicate):
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                root.update()
                second_root.update()
                if predicate():
                    return
                time.sleep(0.02)
            self.fail("Desktop action did not finish")

        def credentials(app, name):
            app.username.delete(0, "end")
            app.username.insert(0, name)
            app.password.insert(0, "test-only password")
            app.room.insert(0, "design-room")

        try:
            credentials(first, "Alice")
            first.confirm.insert(0, "test-only password")
            first.authenticate("register")
            wait_for(lambda: not first.busy)
            self.assertIn("Account created", first.notice.cget("text"))
            first.password.insert(0, "test-only password")
            first.authenticate("login")
            wait_for(lambda: hasattr(first, "transcript"))
            store.create_user("Bobby", "test-only password")
            credentials(second, "Bobby")
            second.authenticate("login")
            wait_for(lambda: hasattr(second, "transcript"))
            first.message.insert(0, "Hello from the desktop")
            first.send()
            wait_for(lambda: "Hello from the desktop" in second.transcript.get("1.0", "end"))
            wait_for(lambda: not first.busy)
            first.message.insert(0, "x" * 4097)
            first.send()
            wait_for(lambda: not first.busy)
            self.assertIn("exceeds", first.transcript.get("1.0", "end"))
            self.assertEqual(first.message.get(), "x" * 4097)
            first.message.delete(0, "end")
            first.message.insert(0, IMMEDIATE_BLOCK_WORD)
            first.send()
            wait_for(lambda: first.connection is None)
            self.assertIn("[SECURITY]", first.transcript.get("1.0", "end"))
            self.assertNotIn(IMMEDIATE_BLOCK_WORD, second.transcript.get("1.0", "end"))
            self.assertEqual(first.send_button.cget("state"), "disabled")
            second.leave()
            self.assertIn("left the room", second.notice.cget("text"))
        finally:
            first.close()
            second.close()
            stop.set()
            accept_thread.join(timeout=2)
            listener.close()
            for worker in handlers:
                worker.join(timeout=2)
            directory.cleanup()
