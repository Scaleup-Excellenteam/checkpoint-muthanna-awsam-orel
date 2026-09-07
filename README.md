# Authenticated Room Chat Server

This project provides a concurrent TCP room-chat server, an interactive client,
and a small REST API. It includes persistent user accounts, message-size limits,
TLS support, server-side DLP enforcement, IP reputation checks, and internal
security logging.

Python 3.10 or newer is required. The project uses only the Python standard
library.

## Project structure

```text
chat/
    server.py          Concurrent TCP server and room delivery
    client.py          Interactive registration, login, and chat client
    api.py             REST API and health endpoint
    auth.py            User accounts, authentication, and persistent block state
    config.py          Configuration loading and validation
    dlp.py             Server-side DLP policy and normalization
    reputation.py      VirusTotal IP reputation checks and cache
    protocol.py        UTF-8 framing and size limits
    transport.py       TLS configuration
tests/                 Automated tests and test helpers
config.json            Editable application settings and DLP policy
data/                  Runtime database and logs; excluded from Git
README.md              Setup and usage instructions
.gitignore             Runtime and secret-file exclusions
```

## Run locally

Run all commands from the project root.

Start the server:

```powershell
python -m chat.server
```

Open another PowerShell window and start a client:

```powershell
python -m chat.client
```

### Web interface (recommended)

Keep `python -m chat.server` running. In a second terminal in the project root:

```powershell
python -m chat.web
```

Open **http://127.0.0.1:8765** in your browser. Create an account, then sign in
and enter a room code, or leave it blank to generate one. Share the code with
your teammates. To test two accounts on one computer, use a normal browser
window and a private/incognito window (ordinary tabs share the same session).

The responsive web UI uses a local Python HTTP bridge to the existing TCP
server. The server still owns authentication, room routing, DLP, and reputation
decisions. The bridge binds only to loopback; each teammate runs it locally.
For a remote TLS chat server, use:

```powershell
python -m chat.web --host 10.124.38.204 --tls --cafile server.pem
```

Use `--web-port 8766` if port 8765 is occupied. Browser sessions use HttpOnly,
SameSite cookies, and requests from other origins are rejected. Passwords are
not retained by the bridge. A closed browser session expires after two minutes
without polling. Messages are polled every 700 ms; outgoing bubbles indicate
submission, not confirmed delivery. Refreshing loses locally displayed history.
No additional Python packages, npm installation, or build step is required.

### Desktop interface (optional)

For the graphical client, keep the server running and launch:

```powershell
python -m chat.gui
```

Create an account, then sign in with a room code (leave it empty to generate one).
Use **Copy room code** to invite another client. Press Enter or **Send** to submit
a message. **Leave room / sign out** returns to the login screen. Server security
notices appear in the conversation; a disconnected session must sign in again.
Local outgoing messages indicate submission, not confirmed delivery, because the
existing protocol does not acknowledge individual messages. History is session-only.

The desktop client uses Python's bundled Tkinter and the existing TCP protocol.
It supports the same `--host`, `--port`, `--tls`, `--cafile`, and
`--server-hostname` options as the command-line client. For example:

```powershell
python -m chat.gui --host 10.124.38.204 --tls --cafile server.pem
```

The server's authentication, DLP policy, and reputation checks remain unchanged.

In the client:

1. Select `1. Register` and create an account.
2. Select `2. Login` and enter the same credentials.
3. Enter a room code. Users with the same room code can exchange messages.
4. Type `exit` to leave the current chat session.

Usernames contain 3–32 ASCII letters, digits, `_`, or `-` and are
case-sensitive. Passwords must contain at least 8 characters and no more than
256 UTF-8 bytes. Password input is hidden and registration asks for confirmation.

The default chat address is `127.0.0.1:55555`. The REST API is available at
`http://127.0.0.1:8000`.

## Configuration

All operational limits and durations are stored in `config.json`. Edit that one
file and restart the server and clients to apply a change. Command-line `--host`,
`--port`, and `--api-port` arguments override the corresponding network defaults
for that process.

| Section | Controls |
| --- | --- |
| `network` | Host, TCP and API ports, timeouts, generated room size, API version |
| `limits` | Message, room, authentication, username, and password limits |
| `authentication` | PBKDF2 work factor and salt size |
| `storage` | SQLite database and internal log paths |
| `dlp` | Vocabulary, quota fractions, block duration, and public block template |
| `anti_bot` | VirusTotal timeout, cache duration, threshold, and endpoint |
| `tls` | Minimum accepted TLS version |

The configuration is validated during startup. Missing fields, invalid ranges,
duplicate DLP terms, and broken message templates stop startup with a clear
error instead of silently applying an invalid value. Keep `{minutes}` in the DLP
public-message template and `{address}` in the VirusTotal URL template.

`legacy_pbkdf2_iterations` records the work factor used by databases created by
older versions of this project. Leave it unchanged when upgrading an existing
database. New accounts use `pbkdf2_iterations`, and each account stores its own
work factor so future changes do not break existing passwords.

The VirusTotal API key remains in the `VIRUSTOTAL_API_KEY` environment variable
and is deliberately excluded from `config.json` so it is not committed as a
secret.

## REST API and health check

The REST API uses the same SQLite account database as the TCP server. All
responses are JSON.

| Method | Path | Successful result |
| --- | --- | --- |
| `GET` | `/health` | Service, database, and Anti-Bot status |
| `POST` | `/register` | `201` after creating an account |
| `POST` | `/login` | `200` after successful authentication |

Check the service:

```powershell
curl.exe http://127.0.0.1:8000/health
```

With no VirusTotal key configured, the response is:

```json
{
  "status": "ok",
  "database": "ok",
  "anti_bot": "not_configured"
}
```

Register and log in through REST:

```powershell
curl.exe -X POST http://127.0.0.1:8000/register -H "Content-Type: application/json" -d '{"username":"Orel","password":"password123"}'
curl.exe -X POST http://127.0.0.1:8000/login -H "Content-Type: application/json" -d '{"username":"Orel","password":"password123"}'
```

Registration and login request bodies are limited to 2,048 bytes. Duplicate
registration returns `409`, invalid input returns `400`, and invalid credentials
return `401`. Login for a temporarily blocked account returns `403` with the
remaining block time.

The `/health` endpoint is public. IP reputation checks apply to TCP connections,
`/register`, and `/login`.

## VirusTotal Anti-Bot check

To enable reputation checks for public client IP addresses, set the environment
variable before starting the server:

```powershell
$env:VIRUSTOTAL_API_KEY = "your-api-key"
python -m chat.server
```

The server blocks an address when at least one VirusTotal engine reports it as
malicious. Results are cached for 10 minutes. Local and private addresses are
allowed without a VirusTotal request.

The API key is optional. If it is missing, the server does not make a VirusTotal
network request, returns an `UNKNOWN` verdict, records the reason internally,
and allows the connection to continue. VirusTotal errors use the same fail-open
behavior, so the external service does not prevent the chat server from working.

## DLP behavior

The DLP policy and monitored vocabulary remain on the server. They are not sent
to clients and are not exposed through REST responses. Normalization ignores
punctuation and combining marks for inspection, while the original message text
is preserved for delivery.

Each account has a persistent distinct-term counter. With the current 30-term
policy, 21 distinct matches are allowed and the next new match blocks the
account. Repeating an already counted term does not increase the counter. The
policy also contains an internal immediate-block rule.

Messages below the limit are delivered normally without a DLP response. A
message that triggers a block is stopped before delivery, all active connections
for that account are disconnected, and the account remains blocked for 10
minutes. The client receives only this general response:

```text
[SECURITY] Account blocked for 10 minutes: prohibited-word usage limit exceeded.
```

The response does not identify the matched term or reveal the counter. After
the block expires, the account resumes at 50% of the allowed quota. DLP counters
and block times are stored in SQLite and survive server restarts.

## Message and input limits

| Input | Limit |
| --- | --- |
| Chat message | 4,096 UTF-8 bytes before the username prefix |
| Room code | 64 bytes; ASCII letters, digits, `_`, or `-` |
| Registration or login request | 2,048 bytes |
| Password | 8 or more characters and at most 256 UTF-8 bytes |

The protocol uses newline-delimited UTF-8 frames. Invalid UTF-8, terminal control
characters, and oversized frames are rejected. Limits are measured in bytes,
so non-ASCII characters may use more than one byte.

## Accounts and internal logs

Accounts are stored in `data/users.db`. Passwords are stored as independently
salted PBKDF2-HMAC-SHA256 hashes with 600,000 iterations. Plain-text passwords
are never stored.

Internal logs are written to `data/server.log`. They include connections,
authentication results, room membership, message size and delivery counts, DLP
decisions and private evidence, account block events, VirusTotal evidence, and
REST response statuses. Passwords, the VirusTotal API key, and complete chat
messages are not logged. The log is not available through the client or REST API.

The `data` directory and PEM/key files are excluded from Git. If you choose a
database path outside `data`, exclude that path separately.

## TLS and access from another computer

Plain TCP is accepted only on a loopback address. A server bound to a network
address must use TLS. For a local-network demonstration, create a certificate
that contains the server's real IP address:

```powershell
openssl req -x509 -newkey rsa:2048 -nodes -days 30 -keyout server.key -out server.pem -subj "/CN=chat-server" -addext "subjectAltName=IP:10.124.38.204"
python -m chat.server --host 10.124.38.204 --cert server.pem --key server.key
```

Copy only `server.pem` to each client through a trusted channel. Keep
`server.key` on the server. Start each client with:

```powershell
python -m chat.client --host 10.124.38.204 --tls --cafile server.pem
```

The client validates the certificate and server identity. When TLS is enabled
on the server, the REST API also uses HTTPS.

## Run the tests

```powershell
python -m unittest discover -s tests -v
```

The suite covers account persistence, password validation, concurrent
registration, room isolation, sender identity, REST and `/health`, message-size
limits, DLP normalization and blocking, account-wide disconnection, persistent
quota state, Anti-Bot caching and fail-open behavior, and verified TLS chat.
TLS integration tests require OpenSSL; Git for Windows' bundled OpenSSL is also
detected.

## Current limitations

The server does not rate-limit login attempts or messages. Any authenticated
user who knows a room code can join that room. Rooms and message history are
kept in memory only, and a slow receiving client can delay broadcasts while the
shared send lock is held.
