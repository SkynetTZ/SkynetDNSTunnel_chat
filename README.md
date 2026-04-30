# SkynetDNSTunnel_chat
DNS-over-UDP messaging system that tunnels chat traffic through DNS TXT queries and responses.

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
