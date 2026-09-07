"""Desktop client. Run with python -m chat.gui; no extra packages required."""

import argparse
from datetime import datetime
import queue
import secrets
import socket
import threading
import tkinter as tk
from tkinter import scrolledtext

from .client import account_request
from .config import NETWORK, LIMITS
from .protocol import MAX_MESSAGE_BYTES, MAX_ROOM_BYTES, MAX_SERVER_MESSAGE_BYTES, read_message, send_message
from .transport import client_context

BG, PANEL, CARD = "#f7f5ef", "#ffffff", "#edeae2"
TEXT, MUTED, ACCENT = "#203c33", "#69766e", "#d4512e"
DARK, GREEN, LINE = "#203c33", "#dfeadd", "#dedfd6"
WARNING = "#99501f"


class Connection:
    """Keep network operations off the Tk event thread."""

    def __init__(self, options):
        self.options = options
        self.socket = None
        self.stream = None

    def open(self):
        context = client_context(self.options.host, self.options.tls, self.options.cafile)
        self.socket = socket.create_connection(
            (self.options.host, self.options.port), timeout=NETWORK["handshake_timeout_seconds"]
        )
        if context:
            self.socket = context.wrap_socket(self.socket, server_hostname=self.options.server_hostname or self.options.host)
        self.stream = self.socket.makefile("rb")
        verdict = self.read()
        if verdict is None or verdict.startswith("[ANTI-BOT] BLOCK:"):
            raise ValueError(verdict or "Server disconnected.")
        return verdict

    def read(self):
        return read_message(self.stream, MAX_SERVER_MESSAGE_BYTES)

    def close(self):
        if self.socket:
            try:
                self.socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.socket.close()


class ChatApp:
    def __init__(self, root, options):
        self.root, self.options = root, options
        self.events = queue.Queue()
        self.connection = None
        self.generation = 0
        self.busy = False
        root.title("Secret Slice — Team chat")
        root.geometry("1180x820")
        root.minsize(1080, 800)
        root.configure(bg=BG)
        root.option_add("*Font", "{Segoe UI} 11")
        root.protocol("WM_DELETE_WINDOW", self.close)
        self.show_login()
        root.after(80, self.poll)

    def label(self, parent, text, size=11, color=TEXT, bold=False):
        return tk.Label(parent, text=text, bg=parent.cget("bg"), fg=color,
                        font=("Segoe UI", size, "bold" if bold else "normal"), anchor="w", justify="left")

    def button(self, parent, text, command, primary=False):
        return tk.Button(parent, text=text, command=command, bg=ACCENT if primary else CARD,
                         fg="white" if primary else TEXT, activebackground="#b84123" if primary else LINE,
                         activeforeground="white" if primary else TEXT,
                         relief="flat", bd=0, padx=18, pady=11, cursor="hand2")

    def field(self, parent, title, secret=False):
        self.label(parent, title, color=MUTED).pack(anchor="w", pady=(12, 6))
        entry = tk.Entry(parent, bg=BG, fg=TEXT, insertbackground=TEXT, relief="flat",
                         highlightthickness=1, highlightbackground=LINE, highlightcolor=ACCENT,
                         font=("Segoe UI", 12), show="●" if secret else "")
        entry.pack(fill="x", ipady=9)
        return entry

    def clear(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def show_login(self, notice=""):
        self.clear()
        self.busy = False
        self.auth_mode = "login"
        header = tk.Frame(self.root, bg=BG)
        header.pack(fill="x", padx=38, pady=(24, 16))
        self.label(header, "◕  secret slice", 21, TEXT, True).pack(side="left")
        self.label(header, "A LITTLE SPACE FOR YOUR PEOPLE", 9, MUTED).pack(side="right")
        tk.Frame(self.root, bg=LINE, height=1).pack(fill="x", padx=38)
        footer = tk.Frame(self.root, bg=BG)
        footer.pack(side="bottom", fill="x", padx=38, pady=18)
        self.label(footer, "TSPO  /  THE TEAM'S TABLE", 9, MUTED).pack(side="left")
        mode = "TLS connection" if self.options.tls else "Local connection"
        self.label(footer, f"{mode}  ·  {self.options.host}:{self.options.port}", 9, MUTED).pack(side="right")
        body = tk.Frame(self.root, bg=BG)
        body.pack(fill="both", expand=True, padx=38, pady=24)
        left = tk.Frame(body, bg=BG, width=450)
        left.pack(side="left", fill="y")
        left.pack_propagate(False)
        self.label(left, "PULL UP A CHAIR", 10, ACCENT, True).pack(anchor="w", pady=(24, 18))
        self.label(left, "Big ideas.\nSmall circles.", 35, TEXT, True).pack(anchor="w")
        self.label(left, "A room for your team. A place for the ideas,\nplans, and conversations that bring you together.", 11, MUTED).pack(anchor="w", pady=18)
        art = tk.Canvas(left, bg=BG, height=220, width=420, highlightthickness=0)
        art.pack(anchor="w", pady=8)
        art.create_oval(35, 10, 335, 220, fill=GREEN, outline="")
        art.create_rectangle(20, 40, 295, 120, fill=PANEL, outline=LINE)
        art.create_oval(37, 56, 71, 90, fill=ACCENT, outline="")
        art.create_text(54, 73, text="A", fill="white", font=("Segoe UI", 11, "bold"))
        art.create_text(86, 65, text="A place to start something.", anchor="w", fill=TEXT, font=("Segoe UI", 10, "bold"))
        art.create_line(86, 86, 257, 86, fill=LINE, width=4)
        art.create_line(86, 100, 210, 100, fill=LINE, width=4)
        art.create_rectangle(120, 135, 399, 199, fill=DARK, outline="")
        art.create_text(142, 158, text="Better when we're together.", anchor="w", fill="white", font=("Segoe UI", 10, "bold"))
        art.create_text(142, 180, text="YOUR NEXT CONVERSATION STARTS HERE", anchor="w", fill="#b7cbbb", font=("Segoe UI", 7))
        self.label(left, "YOUR ACCOUNT   /   YOUR ROOM   /   YOUR TEAM", 8, MUTED).pack(anchor="w", pady=12)
        right = tk.Frame(body, bg=PANEL, highlightbackground=LINE, highlightthickness=1)
        right.pack(side="right", fill="both", expand=True, padx=(24, 0))
        form = tk.Frame(right, bg=PANEL)
        form.pack(fill="both", expand=True, padx=30, pady=26)
        tabs = tk.Frame(form, bg=PANEL)
        tabs.pack(fill="x", pady=(0, 15))
        self.signin_tab = self.button(tabs, "Sign in", lambda: self.set_auth_mode("login"))
        self.signin_tab.pack(side="left", fill="x", expand=True)
        self.signup_tab = self.button(tabs, "Create account", lambda: self.set_auth_mode("register"))
        self.signup_tab.pack(side="left", fill="x", expand=True, padx=(5, 0))
        self.form_title = self.label(form, "Welcome back.", 24, bold=True)
        self.form_title.pack(anchor="w")
        self.form_subtitle = self.label(form, "Your next conversation is waiting.", 10, MUTED)
        self.form_subtitle.pack(anchor="w", pady=(5, 8))
        self.username = self.field(form, "Username")
        self.password = self.field(form, f"Password  ·  {LIMITS['password_min_characters']}+ characters", True)
        self.confirm_group = tk.Frame(form, bg=PANEL)
        self.confirm = self.field(self.confirm_group, "Confirm password", True)
        self.room_group = tk.Frame(form, bg=PANEL)
        self.room = self.field(self.room_group, "Room code  ·  optional")
        self.label(self.room_group, "Leave blank to create a new room for your team.", 9, MUTED).pack(anchor="w", pady=(7, 0))
        self.actions = tk.Frame(form, bg=PANEL)
        self.actions.pack(fill="x", pady=(20, 0))
        self.login_button = self.button(self.actions, "Join the conversation  →", lambda: self.authenticate("login"), True)
        self.register_button = self.button(self.actions, "Create my account  →", lambda: self.authenticate("register"), True)
        self.notice = self.label(form, notice, 10, MUTED)
        self.notice.configure(wraplength=390)
        self.notice.pack(anchor="w", pady=12)
        self.set_auth_mode("login")
        self.username.focus_set()
        self.root.bind("<Return>", lambda event: self.authenticate(self.auth_mode))

    def set_auth_mode(self, mode):
        if self.busy:
            return
        self.auth_mode = mode
        self.confirm_group.pack_forget()
        self.room_group.pack_forget()
        self.login_button.pack_forget()
        self.register_button.pack_forget()
        registering = mode == "register"
        group = self.confirm_group if registering else self.room_group
        group.pack(fill="x", before=self.actions)
        (self.register_button if registering else self.login_button).pack(fill="x")
        self.form_title.configure(text="Find your people." if registering else "Welcome back.")
        self.form_subtitle.configure(text="One account. A seat at your team's table." if registering else "Your next conversation is waiting.")
        self.signin_tab.configure(bg=CARD if registering else DARK, fg=TEXT if registering else "white")
        self.signup_tab.configure(bg=DARK if registering else CARD, fg="white" if registering else TEXT)

    def authenticate(self, action):
        if self.busy:
            return
        username, password = self.username.get().strip(), self.password.get()
        room = self.room.get().strip() or secrets.token_urlsafe(NETWORK["generated_room_token_bytes"])
        if not username or not password:
            self.notice.configure(text="Enter your username and password.", fg=WARNING)
            return
        if action == "register" and password != self.confirm.get():
            self.notice.configure(text="Passwords do not match.", fg=WARNING)
            return
        self.busy = True
        self.login_button.configure(state="disabled")
        self.register_button.configure(state="disabled")
        self.notice.configure(text="Connecting…", fg=MUTED)
        self.password.delete(0, "end")
        self.confirm.delete(0, "end")
        connection = Connection(self.options)
        self.connection = connection
        generation = self.generation

        def work():
            try:
                verdict = connection.open()
                reply = account_request(connection.socket, connection.stream, action, username, password)
                expected = "[REGISTER] OK" if action == "register" else "[AUTH] OK"
                if reply != expected:
                    raise ValueError(reply or "Server disconnected.")
                if action == "register":
                    self.events.put((generation, "registered", "Account created. Enter your password and sign in."))
                    return
                send_message(connection.socket, room, MAX_ROOM_BYTES)
                reply = connection.read()
                if reply != f"[ROOM] Joined room: {room}":
                    raise ValueError(reply or "Could not join room.")
                connection.socket.settimeout(None)
                self.events.put((generation, "joined", (username, room, verdict)))
                while True:
                    message = connection.read()
                    if message is None:
                        break
                    self.events.put((generation, "message", message))
                self.events.put((generation, "disconnected", "Connection closed. Sign in again to reconnect."))
            except (OSError, ValueError) as error:
                self.events.put((generation, "error", str(error)))
            finally:
                connection.close()
                if connection.stream:
                    connection.stream.close()

        threading.Thread(target=work, daemon=True).start()

    def show_chat(self, username, room, verdict):
        self.clear()
        self.busy = False
        self.chat_username = username
        sidebar = tk.Frame(self.root, bg=DARK, width=260)
        sidebar.pack(side="left", fill="y")
        sidebar.pack_propagate(False)
        content = tk.Frame(sidebar, bg=DARK)
        content.pack(fill="both", expand=True, padx=22, pady=28)
        self.label(content, "◕  secret slice", 18, "white", True).pack(anchor="w")
        self.label(content, "THE TEAM'S TABLE", 8, "#b7cbbb").pack(anchor="w", pady=(8, 30))
        tk.Frame(content, bg="#496253", height=1).pack(fill="x")
        self.label(content, "WORKSPACE", 9, "#b7cbbb").pack(anchor="w", pady=(26, 10))
        self.label(content, "●  Conversation", 12, "white", True).pack(anchor="w", pady=10)
        self.label(content, "ROOM CODE", 9, "#b7cbbb").pack(anchor="w", pady=(28, 10))
        room_label = self.label(content, "# " + room, 13, "white", True)
        room_label.configure(wraplength=200)
        room_label.pack(anchor="w")
        self.button(content, "Copy invite code  ↗", lambda: self.copy_room(room)).pack(fill="x", pady=14)
        self.label(content, "Good company starts\nwith an invitation.", 10, "#b7cbbb").pack(anchor="w")
        self.label(content, "SESSION", 9, "#b7cbbb").pack(anchor="w", pady=(35, 10))
        self.connection_badge = self.label(content, "●  Connected", 10, "#bfe8bb")
        self.connection_badge.pack(anchor="w")
        self.label(content, "TLS verified" if self.options.tls else "Local connection", 10, "#b7cbbb").pack(anchor="w", pady=6)
        self.button(content, "Sign out  ↗", self.leave).pack(side="bottom", fill="x", pady=12)
        account = self.label(content, "YOUR ACCOUNT\n" + username, 11, "white", True)
        account.configure(wraplength=200)
        account.pack(side="bottom", anchor="w")
        main = tk.Frame(self.root, bg=BG)
        main.pack(fill="both", expand=True, padx=30, pady=26)
        top = tk.Frame(main, bg=BG)
        top.pack(fill="x")
        self.label(top, "WORKSPACE  /  CONVERSATION", 9, MUTED).pack(side="left")
        self.label(top, datetime.now().strftime("%A, %d %B"), 9, MUTED).pack(side="right")
        self.label(main, "At the table.", 28, bold=True).pack(anchor="w", pady=(15, 5))
        self.label(main, "The ideas, updates, and little things worth sharing.", 11, MUTED).pack(anchor="w", pady=(0, 18))
        self.status = self.label(main, "●  Room connected  ·  Server security checks are active", 10, TEXT)
        self.status.configure(bg=GREEN, padx=12, pady=10)
        self.status.configure(wraplength=620)
        self.status.pack(fill="x", pady=(0, 16))
        self.transcript = scrolledtext.ScrolledText(main, bg=PANEL, fg=TEXT, relief="flat", bd=0,
                                                  padx=20, pady=18, height=8, wrap="word", state="disabled", font=("Segoe UI", 12))
        self.transcript.pack(fill="both", expand=True)
        self.transcript.tag_configure("meta", foreground=MUTED, font=("Segoe UI", 9, "bold"), spacing1=10, spacing3=6)
        self.transcript.tag_configure("own_meta", foreground=ACCENT, justify="right", font=("Segoe UI", 9, "bold"), spacing1=10, spacing3=6)
        self.transcript.tag_configure("own", foreground=TEXT, background="#fbe9df", justify="right", lmargin1=60, lmargin2=60, rmargin=12, spacing1=10, spacing3=10)
        self.transcript.tag_configure("body", foreground=TEXT, background="#eff3ed", lmargin1=12, lmargin2=12, rmargin=60, spacing1=10, spacing3=10)
        self.transcript.tag_configure("system", foreground=WARNING, font=("Segoe UI", 10), spacing3=8)
        self.append("Welcome to your room", "Invite your team with the room code. This conversation stays here for your current session.", "system")
        self.append("Connection check", verdict, "system")
        composer = tk.Frame(main, bg=PANEL, highlightbackground=LINE, highlightthickness=1)
        composer.pack(fill="x", pady=(20, 8))
        self.message = tk.Entry(composer, bg=PANEL, fg=TEXT, insertbackground=TEXT, relief="flat", font=("Segoe UI", 12))
        self.message.pack(side="left", fill="x", expand=True, ipady=13, padx=12)
        self.send_button = self.button(composer, "Send  →", self.send, True)
        self.send_button.pack(side="right", padx=6, pady=6)
        self.label(main, f"Enter to send  ·  {MAX_MESSAGE_BYTES:,}-byte limit  ·  Delivery is not confirmed", 9, MUTED).pack(anchor="w")
        self.root.bind("<Return>", lambda event: self.send())
        self.message.focus_set()

    def append(self, sender, text, tag=None):
        own = sender.startswith("You ·")
        self.transcript.configure(state="normal")
        self.transcript.insert("end", f"{sender}   ·   {datetime.now():%H:%M}\n", "own_meta" if own else "meta")
        self.transcript.insert("end", text + "\n", tag or ("own" if own else "body"))
        self.transcript.insert("end", "\n")
        self.transcript.configure(state="disabled")
        self.transcript.see("end")

    def send(self):
        if self.busy or self.send_button.cget("state") == "disabled":
            return
        text = self.message.get()
        if not text.strip():
            return
        self.busy = True
        self.send_button.configure(state="disabled")
        self.message.configure(state="disabled")
        generation, connection = self.generation, self.connection

        def work():
            try:
                send_message(connection.socket, text, MAX_MESSAGE_BYTES)
                self.events.put((generation, "sent", text))
            except (OSError, ValueError) as error:
                self.events.put((generation, "send_error", str(error)))
        threading.Thread(target=work, daemon=True).start()

    def poll(self):
        while not self.events.empty():
            generation, kind, value = self.events.get()
            if generation != self.generation:
                continue
            if kind == "joined":
                self.show_chat(*value)
            elif kind in ("sent", "send_error"):
                self.busy = False
                if self.connection is not None:
                    self.send_button.configure(state="normal")
                    self.message.configure(state="normal")
                if kind == "sent":
                    self.message.delete(0, "end")
                    self.append("You · submitted", value)
                else:
                    self.append("Could not send", value, "system")
            elif kind == "message":
                if value.startswith("["):
                    self.append("Server notice", value, "system")
                    self.status.configure(text=value, fg=WARNING, bg="#fff0d9")
                else:
                    sender, _, body = value.partition(": ")
                    self.append(sender, body)
            elif hasattr(self, "status") and self.status.winfo_exists():
                self.append("Disconnected", value, "system")
                self.status.configure(text=value, fg=WARNING, bg="#fff0d9")
                self.connection_badge.configure(text="●  Disconnected", fg="#ffc38b")
                self.send_button.configure(state="disabled")
                self.message.configure(state="disabled")
                self.connection = None
            else:
                self.busy = False
                if kind == "registered":
                    self.set_auth_mode("login")
                self.notice.configure(text=value, fg=TEXT if kind == "registered" else WARNING)
                self.login_button.configure(state="normal")
                self.register_button.configure(state="normal")
        self.root.after(80, self.poll)

    def copy_room(self, room):
        self.root.clipboard_clear()
        self.root.clipboard_append(room)
        self.status.configure(text="Room code copied. Share it with your teammate.", fg=TEXT, bg=GREEN)

    def leave(self):
        self.generation += 1
        if self.connection:
            self.connection.close()
        self.connection = None
        self.show_login("You left the room. Sign in to join another room.")

    def close(self):
        if self.connection:
            self.connection.close()
        self.root.destroy()


def main():
    parser = argparse.ArgumentParser(description="Secret Slice desktop chat")
    parser.add_argument("--host", default=NETWORK["host"])
    parser.add_argument("--port", type=int, default=NETWORK["chat_port"])
    parser.add_argument("--tls", action="store_true")
    parser.add_argument("--cafile")
    parser.add_argument("--server-hostname")
    options = parser.parse_args()
    # Use actual screen pixels on Windows, avoiding blurry scaled text.
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except (AttributeError, OSError):
        pass
    root = tk.Tk()
    ChatApp(root, options)
    root.mainloop()


if __name__ == "__main__":
    main()
