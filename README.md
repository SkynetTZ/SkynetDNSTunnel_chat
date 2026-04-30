# SkynetDNSTunnel_chat
DNS-over-UDP messaging system that tunnels chat traffic through DNS TXT queries and responses.

<img width="1534" height="475" alt="WhatsApp Image 2026-04-30 at 11 38 44" src="https://github.com/user-attachments/assets/3d27217e-4a9e-4357-9d52-1425d53309be" />

Skynet UDP Tunnel Chat is a Python-based DNS-over-UDP messaging system that tunnels chat traffic through DNS TXT queries and responses.

DNS-over-UDP chat prototype with:

- `teamserver.py` – asyncio DNS TXT relay + SQLite-backed chat state  
- `chat.py` – standalone terminal client (no `chat2.py` dependency)  
- `common_protocol.py` – shared DNS payload encoding/signing helpers  

Designed for WAN testing, NAT‑friendly delivery (poll‑based), and command‑driven terminal use.

## Features
- Room‑based chat using a shared secret (`chat secret`)  
- Private messaging (`/w <user> <message>`)  
- Presence list with online/offline users  
- Join/leave system notifications  
- Small file transfer over DNS in chunks (with SHA‑256 verification)  
- Admin moderation for user `auxgrep`: 
  - `/ban <user>`  
  - `/unban <user>` (or `/unb <user>`)  
  - `/remove <user>`  
- Request signing + replay protection + rate limiting
    
# HOW IT WORKS
------------

DNS is request/response over UDP, so the client continuously polls for inbox updates.
Messages and files are encoded as JSON payloads carried in DNS TXT records.

Server state is persisted in SQLite (chat_state.db) and includes:

- username
- room identifier (derived from chat secret)
- session token
- last seen timestamp
- ban state

# REQUIREMENTS
------------

- Python 3.9+
- UDP access between client and server
- Ability to bind your chosen UDP port (port 53 may require admin/root privileges)

Install dependencies:

    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt

# START SERVER
------------

Set the admin password used when logging in as auxgrep:

    export SKYNET_ADMIN_CODE="change-this-admin-code"

Run:

    sudo python3 teamserver.py

Main server settings are in teamserver.py:

- SERVER_HOST
- SERVER_PORT
- SERVER_DOMAIN
- ONLINE_WINDOW_MS
- MAX_REQS_PER_WINDOW

# START CLIENTS
-------------

Run in two or more terminals:

    python3 chat.py

Each client will prompt for:

1. Server IP
2. Server port
3. Username
4. Chat secret
5. Admin password (only when username is auxgrep)

# CLIENT COMMANDS
---------------

- Plain text                - Send to room peers
- /msg <text>               - Explicit room message
- /users or /user           - List users in your room
- /w <user> <message>       - Send a private message
- /sendfile <path>          - Send file to the room
- /sendfileto <user> <path> - Send file privately
- /files                    - Show received file notifications
- /savefile <file_id> <output_path> - Fetch and save a file
- /clear                    - Clear terminal view
- /quit                     - Exit

Admin-only commands (user auxgrep):

- /ban <user>
- /unban <user> or /unb <user>
- /remove <user>

# SECURITY NOTES
--------------

Implemented protections include:

- Admin password from environment variable (SKYNET_ADMIN_CODE)
- Room secret hashed (secret_room_id) before DB storage
- HMAC-signed authenticated requests
  - Nonce + timestamp replay window checks
- Per-source request rate limiting
- Banned users rejected even with stale tokens

FILE TRANSFER NOTES
-------------------

- Maximum file size is intentionally limited (~350 KB)
- Files are uploaded in chunked base64 segments
- Receiver fetches file data chunk-by-chunk via /savefile
- SHA-256 is verified on save

WINDOWS TERMINAL NOTE
---------------------

If you see odd prompt behavior in older Windows consoles, prefer Windows Terminal or PowerShell.
For tab completion support on Windows, install:

    pip install pyreadline3

DISCLAIMER
----------

This is a prototype, NOT a production-ready secure messaging platform.
If deploying beyond testing, add transport hardening, key management, monitoring, and abuse controls.
