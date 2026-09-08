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
web/                   Responsive browser UI (HTML, CSS, and JavaScript)
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

Stop the server with `Ctrl+C` in its terminal. The listener checks for interrupts
every `network.accept_poll_seconds` (0.5 seconds by default), including while
waiting for the first client. In VS Code, focus the terminal and clear any text
selection first. If an older running server is stuck, use the terminal's trash
button to terminate that terminal, then open a new one and restart the server.

Open the web application in a browser:

```text
http://127.0.0.1:8000/
```

The browser UI supports registration, login, creating a group, joining an
existing group, group messaging, leaving a group, returning to the group lobby,
and selecting another group. It is responsive for desktop and mobile screens.

Open another PowerShell window and start a client:

```powershell
python -m chat.client
```

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
| `web` | Browser polling, session lifetime, and room-history size |
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

The VirusTotal API key can be set in the `VIRUSTOTAL_API_KEY` environment variable
or the project-root `.env` file (excluded from Git). It is deliberately excluded
from `config.json` so it is not committed as a secret.

## REST API and health check

The REST API uses the same SQLite account database as the TCP server. All
responses are JSON.

| Method | Path | Successful result |
| --- | --- | --- |
| `GET` | `/health` | Service, database, and Anti-Bot status |
| `POST` | `/register` | `201` after creating an account |
| `POST` | `/login` | `200` with an authenticated web session token |
| `GET` | `/rooms` | Available groups for a Bearer-authenticated web user |
| `POST` | `/rooms` | Create and enter a new group |
| `POST` | `/rooms/{room}/join` | Join an existing group |
| `POST` | `/rooms/{room}/leave` | Leave a group and return to the lobby |
| `GET/POST` | `/rooms/{room}/messages` | Read or send group messages |
| `POST` | `/logout` | End the current web session |

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

Web clients send the token returned by `/login` in the
`Authorization: Bearer TOKEN` header. The browser UI manages this token in
session storage and removes it on logout or when a session is rejected.

## VirusTotal Anti-Bot check

Create a `.env` file beside `config.json` containing:

```dotenv
VIRUSTOTAL_API_KEY=your-api-key
```

Then start (or restart) the server with `python -m chat.server`. The file is
loaded automatically from the project root. Single-line values may be unquoted,
single-quoted, or double-quoted; blank lines and comments are supported.
An existing environment variable takes precedence over `.env`, including an
empty variable. In PowerShell, use `Remove-Item Env:VIRUSTOTAL_API_KEY
-ErrorAction SilentlyContinue` to remove an old override before restarting.
Never commit your real API key.

To enable reputation checks for public client IP addresses, set the environment
variable instead before starting the server:

```powershell
$env:VIRUSTOTAL_API_KEY = "your-api-key"
python -m chat.server
```

Check `http://127.0.0.1:8000/health` for `"anti_bot": "configured"`. This confirms
that a key was loaded, not that VirusTotal accepted it. To test a real public-IP
lookup using the same configuration, run from the project root:

```powershell
python -c "from chat.reputation import VirusTotalChecker; print(VirusTotalChecker().check('8.8.8.8'))"
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

## Two local LLM agents (optional)

The optional runner connects to the existing REST API as two independent users.
Both agents share one local Ollama model, called sequentially, with separate roles
and histories. You can join their room in the browser to watch. No additional
Python packages or changes to the server/database schema are needed.

The small default model minimizes memory use, but language quality is not
guaranteed. In local acceptance testing, `qwen3:1.7b` sometimes repeated itself
or switched to Chinese despite the Hebrew prompt. The runner checks message
delivery, not fluency. For a larger model option, download `qwen3:4b` with
`ollama pull qwen3:4b` and select it with `--model qwen3:4b`; this uses additional
disk space and memory. Both agents still use the same model sequentially.

Install [Ollama for Windows](https://ollama.com/download/windows), open a new
PowerShell window, and download the default small model once:

```powershell
ollama pull qwen3:1.7b
```

Ollama must be running at `http://127.0.0.1:11434`. The desktop installation
normally starts it automatically; if necessary, run `ollama serve` in a separate
terminal. The model download is about 1.4 GB; actual RAM usage is higher and
generation speed depends on your hardware. Inference is local and requires no
API key or per-request payment.

Start the chat server normally (`python -m chat.server`). In another terminal,
from the project root, run:

```powershell
python -m tools.llm_chat_test --scenario all
```

The runner checks the chat service, public limits and installed model before
creating accounts. It prints the room name and browser URL for each scenario.
Log in with your own browser account, join that room, then press Enter in the
runner's terminal. Observer messages do not trigger the agents or enter their
model histories.

Scenarios:

| Option | Behavior |
| --- | --- |
| `--scenario chat` | 20 alternating Hebrew messages: one agent proposes an activity, the other asks questions and suggests improvements |
| `--scenario security` | Fixed UTF-8 size boundary, repeated/distinct DLP quota, and immediate-block checks; Ollama is not required |
| `--scenario all` | Chat followed by all three security scenarios; the default |

For unattended runs or another local model:

```powershell
python -m tools.llm_chat_test --scenario all --no-pause
python -m tools.llm_chat_test --scenario chat --model qwen3:1.7b --messages 6 --no-pause
python -m tools.llm_chat_test --scenario security --no-pause
```

Use `--server-url` and `--ollama-url` to override the service addresses. HTTPS uses
normal certificate verification. The server must use the same project version
and configuration as the runner; the private DLP policy is read locally and is
never included in model prompts. Security scenarios deliberately send configured
DLP terms through the chat, so allowed test terms are visible to room observers.

Each scenario creates a fresh pair of accounts and a unique room. Accounts remain
in the configured database after logout because the application has no account
deletion API. Rooms/history retain the server's existing lifetime. Only test
accounts are deliberately blocked; the runner does not reset DLP state or change
server policy. TCP, TLS, load and block-expiry coverage remains in the regular
test suite.

Each model call has a 150-token output budget and at most 10 recent messages of
history. Line breaks are converted to spaces for the chat protocol. A turn only
completes when the other account reads the exact text and sender from the server,
with an increasing message ID. Rejected security messages are checked for absence
throughout the delivery window. No send is automatically retried, including when
the connection fails after submission.

Timeouts are configurable: `--model-timeout 120`, `--delivery-timeout 10` and
`--poll-interval 0.5` (seconds). For slow CPU inference, increase the model timeout.
An unexpected block during free conversation fails that scenario; it does not by
itself establish a server bug. A failed assertion allows the next independent
scenario to run; infrastructure failures or Ctrl+C stop the run. Cleanup logs out
active test sessions on a best-effort basis.

Results are saved incrementally to `data/llm-tests/<run-id>/report.json` and
`transcript.txt`, including partial runs, message IDs, generation/delivery timing,
HTTP statuses, cleanup results, and failure source. Passwords and bearer tokens
are excluded. Override the parent directory with `--output-dir`.

Exit codes: `0` = all selected scenarios passed, `1` = an assertion failed,
`2` = infrastructure/configuration failure or interrupted/incomplete execution.
The runner verifies transport behavior and security assertions; it does not use
another LLM to grade conversation quality.

The regular unittest discovery also runs the runner tests against a real local
REST server and a fake Ollama HTTP service, without downloading a model:

```powershell
python -m unittest tests.test_llm_chat_tool -v
```

## Current limitations

The server does not rate-limit login attempts or messages. Any authenticated
user who knows a room code can join that room. Rooms, web sessions, and the
configured amount of recent message history are kept in memory only. A slow
receiving TCP client can delay broadcasts while the shared send lock is held.
