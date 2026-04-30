import asyncio
import hmac
import hashlib
import os
import sqlite3
from collections import defaultdict, deque
from dataclasses import asdict
from typing import Optional
from dnslib import CLASS, QTYPE, RR, DNSHeader, DNSRecord, TXT
from common_protocol import (
    DOMAIN_SUFFIX,
    MAX_CHAT_CHUNK_LEN,
    Message,
    decode_query_payload,
    decode_txt_payload,
    encode_txt_payload,
    new_session_token,
    now_ms,
    secret_room_id,
    sign_payload,
)

# c0nfigs for the server
SERVER_HOST = "0.0.0.0"
SERVER_PORT = 53
SERVER_DOMAIN = DOMAIN_SUFFIX
ADMIN_USERNAME = "auxgrep"
ADMIN_CODE = os.environ.get("SKYNET_ADMIN_CODE", "<INTER YOUR ADMIN CODE HERE>")
ONLINE_WINDOW_MS = 15000
MAX_FILE_BYTES = 350000
AUTH_SKEW_MS = 20000
MAX_REQS_PER_WINDOW = 2000
RATE_WINDOW_MS = 60000


def log(msg: str) -> None:
    print("[server] {}".format(msg), flush=True)


class ChatState:
    def __init__(self) -> None:
        self.db = sqlite3.connect("chat_state.db", check_same_thread=False)
        self._init_db()
        self.inbox: dict[str, deque[Message]] = defaultdict(deque)
        self.partial_incoming: dict[tuple[str, str, str], dict[int, str]] = {}
        self.online_cache: dict[str, set[str]] = {}
        self.file_inbox: dict[str, deque[dict]] = defaultdict(deque)
        self.partial_file_incoming: dict[tuple[str, str, str], dict] = {}
        self.file_store: dict[str, dict] = {}

    def _init_db(self) -> None:
        self.db.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                secret TEXT NOT NULL,
                token TEXT NOT NULL UNIQUE,
                last_seen_ms INTEGER NOT NULL,
                is_banned INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        self.db.commit()

    def is_banned(self, user: str) -> bool:
        cur = self.db.execute("SELECT is_banned FROM users WHERE username = ?", (user,))
        row = cur.fetchone()
        return bool(row and int(row[0]) == 1)

    def register(self, user: str, secret: str) -> tuple[bool, str]:
        if self.is_banned(user):
            return False, "user is banned"
        room_id = secret_room_id(secret)
        token = new_session_token()
        self.db.execute(
            """
            INSERT INTO users(username, secret, token, last_seen_ms, is_banned)
            VALUES (?, ?, ?, ?, 0)
            ON CONFLICT(username) DO UPDATE SET
                secret=excluded.secret,
                token=excluded.token,
                last_seen_ms=excluded.last_seen_ms
            """,
            (user, room_id, token, now_ms()),
        )
        self.db.commit()
        log("register user='{}' room='{}' token='{}'".format(user, room_id[:10], token))
        return True, token

    def users_for_secret(self, secret: str) -> list[str]:
        cur = self.db.execute(
            "SELECT username FROM users WHERE secret = ? AND is_banned = 0 ORDER BY username COLLATE NOCASE",
            (secret,),
        )
        users = [str(row[0]) for row in cur.fetchall()]
        log("users_for_secret secret='{}' users={}".format(secret, users))
        return users

    def _online_users_for_secret(self, secret: str) -> set[str]:
        cutoff = now_ms() - ONLINE_WINDOW_MS
        cur = self.db.execute(
            """
            SELECT username FROM users
            WHERE secret = ? AND is_banned = 0 AND last_seen_ms >= ?
            ORDER BY username COLLATE NOCASE
            """,
            (secret, cutoff),
        )
        return {str(row[0]) for row in cur.fetchall()}

    def users_presence_for_secret(self, secret: str) -> dict:
        all_users = self.users_for_secret(secret)
        online = self._online_users_for_secret(secret)
        online_users = [u for u in all_users if u in online]
        offline_users = [u for u in all_users if u not in online]
        return {"online_users": online_users, "offline_users": offline_users}

    def _enqueue_system_to_secret(self, secret: str, text: str, exclude: Optional[set[str]] = None) -> None:
        recipients = self._online_users_for_secret(secret)
        if exclude:
            recipients = recipients - exclude
        for user in recipients:
            self.inbox[user].append(Message(from_user="[system]", text=text, ts_ms=now_ms()))
        log("system notify secret='{}' recipients={} text='{}'".format(secret, sorted(recipients), text))

    def refresh_presence(self, secret: str) -> None:
        current = self._online_users_for_secret(secret)
        previous = self.online_cache.get(secret, set())
        joined = sorted(current - previous)
        left = sorted(previous - current)
        self.online_cache[secret] = current
        for username in joined:
            self._enqueue_system_to_secret(secret, "{} joined chat".format(username), exclude={username})
        for username in left:
            self._enqueue_system_to_secret(secret, "{} left chat".format(username))

    def user_secret_for_token(self, token: str) -> Optional[tuple[str, str]]:
        cur = self.db.execute("SELECT username, secret, is_banned FROM users WHERE token = ?", (token,))
        row = cur.fetchone()
        if not row:
            log("token lookup failed token='{}'".format(token))
            return None
        if int(row[2]) == 1:
            log("token rejected (banned) token='{}' user='{}'".format(token, str(row[0])))
            return None
        self.db.execute("UPDATE users SET last_seen_ms = ? WHERE token = ?", (now_ms(), token))
        self.db.commit()
        user = str(row[0])
        secret = str(row[1])
        log("token lookup ok token='{}' user='{}' secret='{}'".format(token, user, secret))
        return user, secret

    def send_message_to_secret(self, src_user: str, secret: str, text: str) -> int:
        cur = self.db.execute(
            "SELECT username FROM users WHERE secret = ? AND username != ? AND is_banned = 0",
            (secret, src_user),
        )
        recipients = [str(row[0]) for row in cur.fetchall()]
        for dst_user in recipients:
            self.inbox[dst_user].append(Message(from_user=src_user, text=text, ts_ms=now_ms()))
        log(
            "deliver src='{}' secret='{}' recipients={} text_len={}".format(
                src_user, secret, recipients, len(text)
            )
        )
        return len(recipients)

    def send_private_message(self, src_user: str, secret: str, dst_user: str, text: str) -> bool:
        cur = self.db.execute(
            "SELECT username FROM users WHERE username = ? AND secret = ? AND is_banned = 0",
            (dst_user, secret),
        )
        row = cur.fetchone()
        if not row:
            return False
        self.inbox[dst_user].append(Message(from_user=src_user + " [private]", text=text, ts_ms=now_ms()))
        log("private deliver src='{}' dst='{}' secret='{}' text_len={}".format(src_user, dst_user, secret, len(text)))
        return True

    def file_start(
        self,
        src_user: str,
        secret: str,
        file_id: str,
        filename: str,
        size: int,
        sha256_hex: str,
        total_chunks: int,
        to_user: str = "",
    ) -> tuple[bool, str]:
        if size <= 0 or size > MAX_FILE_BYTES:
            return False, "file size invalid or too large"
        if total_chunks <= 0:
            return False, "invalid total_chunks"
        key = (src_user, secret, file_id)
        self.partial_file_incoming[key] = {
            "filename": filename[:200],
            "size": size,
            "sha256": sha256_hex.lower(),
            "total_chunks": total_chunks,
            "chunks": {},
            "to_user": to_user.strip(),
        }
        log("file_start src='{}' file_id='{}' name='{}' size={} chunks={}".format(src_user, file_id, filename, size, total_chunks))
        return True, "started"

    def file_chunk(self, src_user: str, secret: str, file_id: str, idx: int, chunk_b64: str) -> tuple[bool, str, Optional[int]]:
        key = (src_user, secret, file_id)
        state = self.partial_file_incoming.get(key)
        if not state:
            return False, "file transfer not started", None
        total = int(state["total_chunks"])
        if idx < 0 or idx >= total:
            return False, "invalid chunk index", None
        state["chunks"][idx] = chunk_b64
        if len(state["chunks"]) < total:
            return True, "partial", None

        combined_b64 = "".join(state["chunks"][i] for i in range(total))
        try:
            import base64

            raw = base64.b64decode(combined_b64.encode("ascii"), validate=True)
        except Exception:
            del self.partial_file_incoming[key]
            return False, "invalid file encoding", None

        if len(raw) != int(state["size"]):
            del self.partial_file_incoming[key]
            return False, "size mismatch", None
        digest = hashlib.sha256(raw).hexdigest().lower()
        if digest != str(state["sha256"]):
            del self.partial_file_incoming[key]
            return False, "sha256 mismatch", None

        to_user = str(state.get("to_user", "")).strip()
        if to_user:
            cur = self.db.execute(
                "SELECT username FROM users WHERE username = ? AND secret = ? AND username != ? AND is_banned = 0",
                (to_user, secret, src_user),
            )
            recipients = [str(row[0]) for row in cur.fetchall()]
        else:
            cur = self.db.execute(
                "SELECT username FROM users WHERE secret = ? AND username != ? AND is_banned = 0",
                (secret, src_user),
            )
            recipients = [str(row[0]) for row in cur.fetchall()]
        if not recipients:
            del self.partial_file_incoming[key]
            return False, "no eligible recipients", None

        self.file_store[file_id] = {
            "from_user": src_user,
            "filename": state["filename"],
            "size": state["size"],
            "sha256": state["sha256"],
            "data_b64": combined_b64,
            "recipients": set(recipients),
            "secret": secret,
            "ts_ms": now_ms(),
        }
        for dst_user in recipients:
            self.file_inbox[dst_user].append(
                {
                    "file_id": file_id,
                    "from_user": src_user,
                    "filename": state["filename"],
                    "size": state["size"],
                    "sha256": state["sha256"],
                    "ts_ms": now_ms(),
                }
            )
        del self.partial_file_incoming[key]
        log("file_complete src='{}' file_id='{}' recipients={} size={}".format(src_user, file_id, recipients, len(raw)))
        return True, "complete", len(recipients)

    def ban_user(self, username: str) -> bool:
        cur = self.db.execute("SELECT username FROM users WHERE username = ?", (username,))
        if not cur.fetchone():
            return False
        # Rotate token so any already-connected banned client gets invalidated immediately.
        self.db.execute("UPDATE users SET is_banned = 1, token = ? WHERE username = ?", (new_session_token(), username))
        self.db.commit()
        self.inbox.pop(username, None)
        log("ban_user username='{}'".format(username))
        return True

    def remove_user(self, username: str) -> bool:
        cur = self.db.execute("SELECT username FROM users WHERE username = ?", (username,))
        if not cur.fetchone():
            return False
        self.db.execute("DELETE FROM users WHERE username = ?", (username,))
        self.db.commit()
        self.inbox.pop(username, None)
        log("remove_user username='{}'".format(username))
        return True

    def unban_user(self, username: str) -> bool:
        cur = self.db.execute("SELECT username FROM users WHERE username = ?", (username,))
        if not cur.fetchone():
            return False
        self.db.execute("UPDATE users SET is_banned = 0 WHERE username = ?", (username,))
        self.db.commit()
        log("unban_user username='{}'".format(username))
        return True

    def add_incoming_chunk(
        self,
        src_user: str,
        secret: str,
        msg_id: str,
        idx: int,
        total: int,
        chunk_text: str,
    ) -> tuple[int, str]:
        if total <= 0 or idx < 0 or idx >= total:
            log("invalid chunk src='{}' idx={} total={} msg_id='{}'".format(src_user, idx, total, msg_id))
            return 0, "invalid chunk indexes"
        key = (src_user, secret, msg_id)
        parts = self.partial_incoming.setdefault(key, {})
        parts[idx] = chunk_text
        log(
            "chunk recv src='{}' secret='{}' msg_id='{}' chunk={}/{} chunk_len={}".format(
                src_user, secret, msg_id, idx + 1, total, len(chunk_text)
            )
        )
        if len(parts) < total:
            return 0, "partial"
        full_text = "".join(parts[i] for i in range(total))
        del self.partial_incoming[key]
        log("chunk complete src='{}' msg_id='{}' full_len={}".format(src_user, msg_id, len(full_text)))
        return self.send_message_to_secret(src_user, secret, full_text), "complete"

    def poll(self, user: str, limit: int = 30) -> list[dict]:
        q = self.inbox[user]
        out: list[dict] = []
        for _ in range(min(limit, len(q))):
            out.append(asdict(q.popleft()))
        return out

    def poll_files(self, user: str, limit: int = 5) -> list[dict]:
        q = self.file_inbox[user]
        out: list[dict] = []
        for _ in range(min(limit, len(q))):
            out.append(q.popleft())
        return out

    def fetch_file_chunk(self, user: str, file_id: str, chunk_idx: int, chunk_b64_size: int = 150) -> tuple[bool, dict]:
        entry = self.file_store.get(file_id)
        if not entry:
            return False, {"error": "file not found"}
        if user not in entry["recipients"]:
            return False, {"error": "access denied"}
        data_b64 = str(entry["data_b64"])
        if chunk_b64_size <= 0:
            chunk_b64_size = 150
        total_chunks = (len(data_b64) + chunk_b64_size - 1) // chunk_b64_size
        if chunk_idx < 0 or chunk_idx >= total_chunks:
            return False, {"error": "invalid chunk_idx"}
        start = chunk_idx * chunk_b64_size
        end = min(len(data_b64), start + chunk_b64_size)
        return True, {
            "file_id": file_id,
            "chunk_idx": chunk_idx,
            "total_chunks": total_chunks,
            "chunk_b64": data_b64[start:end],
            "filename": entry["filename"],
            "size": entry["size"],
            "sha256": entry["sha256"],
        }


class DNSChatProtocol(asyncio.DatagramProtocol):
    def __init__(self, state: ChatState, domain_suffix: str) -> None:
        self.state = state
        self.transport: Optional[asyncio.DatagramTransport] = None
        self.domain_suffix = domain_suffix
        self.seen_nonces: dict[str, dict[str, int]] = defaultdict(dict)
        self.rate_buckets: dict[str, list[int]] = defaultdict(list)

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = transport  # type: ignore[assignment]
        log("DNS chat server listening")

    def datagram_received(self, data: bytes, addr) -> None:
        try:
            if not self._allow_rate(addr):
                self._send_error(data, addr, "rate limit exceeded")
                return
            req = DNSRecord.parse(data)
            payload = self._extract_payload(req)
            log("request from={} payload={}".format(addr, payload))
            result = self.handle_command(payload)
            txt_chunks = encode_txt_payload(result)
            log("response to={} result={}".format(addr, result))

            reply = DNSRecord(DNSHeader(id=req.header.id, qr=1, aa=1, ra=1), q=req.q)
            reply.add_answer(
                RR(
                    rname=req.q.qname,
                    rtype=QTYPE.TXT,
                    rclass=CLASS.IN,
                    ttl=0,
                    rdata=TXT(txt_chunks),
                )
            )
            assert self.transport is not None
            self.transport.sendto(reply.pack(), addr)
        except Exception as exc:
            log("datagram exception from={} error={}".format(addr, str(exc)))
            self._send_error(data, addr, str(exc))

    def _allow_rate(self, addr) -> bool:
        key = str(addr[0])
        now = now_ms()
        bucket = self.rate_buckets[key]
        cutoff = now - RATE_WINDOW_MS
        while bucket and bucket[0] < cutoff:
            bucket.pop(0)
        if len(bucket) >= MAX_REQS_PER_WINDOW:
            # Keep this visible in logs so rate-limit drops are diagnosable.
            if len(bucket) % 50 == 0:
                log("rate-limit drop ip='{}' reqs_in_window={}".format(key, len(bucket)))
            return False
        bucket.append(now)
        return True

    def _verify_auth(self, payload: dict) -> tuple[bool, str]:
        cmd = str(payload.get("cmd", ""))
        if cmd == "register":
            return True, ""
        token = str(payload.get("token", ""))
        nonce = str(payload.get("nonce", ""))
        ts_ms = int(payload.get("ts_ms", 0))
        mac = str(payload.get("mac", ""))
        if not token or not nonce or not mac or ts_ms <= 0:
            return False, "missing auth fields"
        if abs(now_ms() - ts_ms) > AUTH_SKEW_MS:
            return False, "stale request"
        token_cache = self.seen_nonces[token]
        if nonce in token_cache:
            return False, "replay detected"
        signed = dict(payload)
        signed.pop("mac", None)
        expected = sign_payload(signed, token)
        if not hmac.compare_digest(mac, expected):
            return False, "invalid mac"
        token_cache[nonce] = ts_ms
        expiry = now_ms() - AUTH_SKEW_MS
        for n, nts in list(token_cache.items()):
            if nts < expiry:
                token_cache.pop(n, None)
        return True, ""

    def _extract_payload(self, req: DNSRecord) -> dict:
        for ar in req.ar:
            if ar.rtype == QTYPE.TXT:
                txt_data = [part.decode("utf-8") if isinstance(part, bytes) else str(part) for part in ar.rdata.data]
                return decode_txt_payload(txt_data)
        qname = str(req.q.qname)
        return decode_query_payload(qname, self.domain_suffix)

    def _send_error(self, data: bytes, addr, reason: str) -> None:
        try:
            req = DNSRecord.parse(data)
            reply = DNSRecord(DNSHeader(id=req.header.id, qr=1, aa=1, ra=1), q=req.q)
            txt = encode_txt_payload({"ok": False, "error": reason})
            reply.add_answer(RR(rname=req.q.qname, rtype=QTYPE.TXT, rclass=CLASS.IN, ttl=0, rdata=TXT(txt)))
            assert self.transport is not None
            self.transport.sendto(reply.pack(), addr)
            log("error response to={} reason={}".format(addr, reason))
        except Exception:
            return

    def handle_command(self, payload: dict) -> dict:
        cmd = payload.get("cmd")
        ok_auth, reason = self._verify_auth(payload)
        if not ok_auth:
            return {"ok": False, "error": reason}
        if cmd == "register":
            user = payload.get("user", "").strip()
            secret = payload.get("secret", "").strip()
            admin_code = payload.get("admin_code", "").strip()
            if not user or not secret:
                return {"ok": False, "error": "user and secret required"}
            if user == ADMIN_USERNAME and admin_code != ADMIN_CODE:
                return {"ok": False, "error": "invalid admin code"}
            ok, register_result = self.state.register(user, secret)
            if not ok:
                return {"ok": False, "error": register_result}
            token = register_result
            self.state.refresh_presence(secret)
            presence = self.state.users_presence_for_secret(secret)
            log(
                "register command completed user='{}' users_count={}".format(
                    user, len(presence["online_users"]) + len(presence["offline_users"])
                )
            )
            return {
                "ok": True,
                "token": token,
                "user": user,
                "users": presence["online_users"] + presence["offline_users"],
                "online_users": presence["online_users"],
                "offline_users": presence["offline_users"],
                "is_admin": user == ADMIN_USERNAME,
            }

        if cmd == "send_chunk":
            token = payload.get("token", "")
            msg_id = payload.get("msg_id", "")
            idx = int(payload.get("chunk_idx", -1))
            total = int(payload.get("chunk_total", -1))
            text = payload.get("chunk_text", "")
            src_info = self.state.user_secret_for_token(token)
            if not src_info:
                return {"ok": False, "error": "invalid token"}
            src_user, secret = src_info
            self.state.refresh_presence(secret)
            if not text or not msg_id:
                return {"ok": False, "error": "msg_id and chunk_text required"}
            if len(text) > MAX_CHAT_CHUNK_LEN:
                return {"ok": False, "error": "chunk too large"}
            delivered, state = self.state.add_incoming_chunk(src_user, secret, msg_id, idx, total, text)
            if state == "partial":
                log("send_chunk partial src='{}' msg_id='{}' idx={} total={}".format(src_user, msg_id, idx, total))
                return {"ok": True, "partial": True, "chunk_idx": idx}
            log("send_chunk complete src='{}' msg_id='{}' delivered_to={}".format(src_user, msg_id, delivered))
            return {"ok": True, "accepted": True, "delivered_to": delivered}

        if cmd == "send_text":
            token = payload.get("token", "")
            text = payload.get("text", "")
            src_info = self.state.user_secret_for_token(token)
            if not src_info:
                return {"ok": False, "error": "invalid token"}
            src_user, secret = src_info
            self.state.refresh_presence(secret)
            if not text:
                return {"ok": False, "error": "text required"}
            delivered = self.state.send_message_to_secret(src_user, secret, text[:4000])
            log("send_text src='{}' delivered_to={} text_len={}".format(src_user, delivered, len(text)))
            return {"ok": True, "accepted": True, "delivered_to": delivered}

        if cmd == "poll":
            token = payload.get("token", "")
            src_info = self.state.user_secret_for_token(token)
            if not src_info:
                return {"ok": False, "error": "invalid token"}
            user, _ = src_info
            self.state.refresh_presence(src_info[1])
            log("poll command user='{}'".format(user))
            return {"ok": True, "messages": self.state.poll(user), "files": self.state.poll_files(user)}

        if cmd == "list_users":
            token = payload.get("token", "")
            src_info = self.state.user_secret_for_token(token)
            if not src_info:
                return {"ok": False, "error": "invalid token"}
            _, secret = src_info
            self.state.refresh_presence(secret)
            log("list_users command secret='{}'".format(secret))
            presence = self.state.users_presence_for_secret(secret)
            return {
                "ok": True,
                "users": presence["online_users"] + presence["offline_users"],
                "online_users": presence["online_users"],
                "offline_users": presence["offline_users"],
            }

        if cmd == "private_send":
            token = payload.get("token", "")
            to_user = payload.get("to_user", "").strip()
            text = payload.get("text", "")
            src_info = self.state.user_secret_for_token(token)
            if not src_info:
                return {"ok": False, "error": "invalid token"}
            src_user, secret = src_info
            self.state.refresh_presence(secret)
            if not to_user or not text:
                return {"ok": False, "error": "to_user and text required"}
            ok = self.state.send_private_message(src_user, secret, to_user, text[:4000])
            if not ok:
                return {"ok": False, "error": "target user not found in your secret"}
            return {"ok": True, "private": True}

        if cmd == "file_start":
            token = payload.get("token", "")
            src_info = self.state.user_secret_for_token(token)
            if not src_info:
                return {"ok": False, "error": "invalid token"}
            src_user, secret = src_info
            file_id = payload.get("file_id", "").strip()
            filename = payload.get("filename", "").strip()
            size = int(payload.get("size", 0))
            sha256_hex = payload.get("sha256", "").strip()
            total_chunks = int(payload.get("total_chunks", 0))
            to_user = payload.get("to_user", "").strip()
            if not file_id or not filename or not sha256_hex:
                return {"ok": False, "error": "file metadata required"}
            ok, msg = self.state.file_start(src_user, secret, file_id, filename, size, sha256_hex, total_chunks, to_user)
            return {"ok": ok, "error": None if ok else msg}

        if cmd == "file_chunk":
            token = payload.get("token", "")
            src_info = self.state.user_secret_for_token(token)
            if not src_info:
                return {"ok": False, "error": "invalid token"}
            src_user, secret = src_info
            file_id = payload.get("file_id", "").strip()
            idx = int(payload.get("chunk_idx", -1))
            chunk_b64 = payload.get("chunk_b64", "")
            ok, state, delivered = self.state.file_chunk(src_user, secret, file_id, idx, chunk_b64)
            if not ok:
                return {"ok": False, "error": state}
            out = {"ok": True, "state": state}
            if delivered is not None:
                out["delivered_to"] = delivered
            return out

        if cmd == "file_fetch_chunk":
            token = payload.get("token", "")
            src_info = self.state.user_secret_for_token(token)
            if not src_info:
                return {"ok": False, "error": "invalid token"}
            user, _ = src_info
            file_id = payload.get("file_id", "").strip()
            chunk_idx = int(payload.get("chunk_idx", -1))
            chunk_size = int(payload.get("chunk_b64_size", 150))
            ok, data = self.state.fetch_file_chunk(user, file_id, chunk_idx, chunk_size)
            if not ok:
                return {"ok": False, "error": data["error"]}
            data["ok"] = True
            return data

        if cmd == "admin_ban":
            token = payload.get("token", "")
            target = payload.get("target", "").strip()
            src_info = self.state.user_secret_for_token(token)
            if not src_info:
                return {"ok": False, "error": "invalid token"}
            src_user, _ = src_info
            if src_user != ADMIN_USERNAME:
                return {"ok": False, "error": "admin only"}
            if not target or target == ADMIN_USERNAME:
                return {"ok": False, "error": "invalid target"}
            ok = self.state.ban_user(target)
            return {"ok": ok, "error": None if ok else "target user not found"}

        if cmd == "admin_remove":
            token = payload.get("token", "")
            target = payload.get("target", "").strip()
            src_info = self.state.user_secret_for_token(token)
            if not src_info:
                return {"ok": False, "error": "invalid token"}
            src_user, _ = src_info
            if src_user != ADMIN_USERNAME:
                return {"ok": False, "error": "admin only"}
            if not target or target == ADMIN_USERNAME:
                return {"ok": False, "error": "invalid target"}
            ok = self.state.remove_user(target)
            return {"ok": ok, "error": None if ok else "target user not found"}

        if cmd == "admin_unban":
            token = payload.get("token", "")
            target = payload.get("target", "").strip()
            src_info = self.state.user_secret_for_token(token)
            if not src_info:
                return {"ok": False, "error": "invalid token"}
            src_user, _ = src_info
            if src_user != ADMIN_USERNAME:
                return {"ok": False, "error": "admin only"}
            if not target or target == ADMIN_USERNAME:
                return {"ok": False, "error": "invalid target"}
            ok = self.state.unban_user(target)
            return {"ok": ok, "error": None if ok else "target user not found"}

        return {"ok": False, "error": "unknown cmd"}


async def main() -> None:
    loop = asyncio.get_running_loop()
    state = ChatState()
    await loop.create_datagram_endpoint(
        lambda: DNSChatProtocol(state, SERVER_DOMAIN),
        local_addr=(SERVER_HOST, SERVER_PORT),
    )
    print(f"Server config: host={SERVER_HOST} port={SERVER_PORT} domain={SERVER_DOMAIN}")

    while True:
        await asyncio.sleep(3600)


if __name__ == "__main__":
    asyncio.run(main())
