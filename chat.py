import base64
import hashlib
import os
import random
import socket
import sys
import threading
import time
import uuid
import getpass
from typing import Optional
from contextlib import contextmanager
try:
    import readline  
except Exception:
    readline = None  
from dnslib import CLASS, QTYPE, RR, DNSRecord, TXT
from common_protocol import DOMAIN_SUFFIX, MAX_CHAT_CHUNK_LEN, decode_txt_payload, encode_txt_payload, now_ms, sign_payload, split_text_chunks

MAX_FILE_BYTES = 350000
FILE_CHUNK_B64_LEN = 120


class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"

def color(text: str, tone: str) -> str:
    return "{}{}{}".format(tone, text, C.RESET)

class DNSChatClient:
    def __init__(self, server_host: str, server_port: int, domain_suffix: str = DOMAIN_SUFFIX) -> None:
        self.server_host = server_host
        self.server_port = server_port
        self.domain_suffix = domain_suffix
        self.token: Optional[str] = None
        self.username: Optional[str] = None
        self.is_admin = False
        self.received_files: dict[str, dict] = {}
        self.io_lock = threading.Lock()
        self.pause_poll = threading.Event()

    def _request(self, payload: dict, timeout_s: float = 2.0) -> dict:
        # Keep QNAME short to avoid DNS label-length limits.
        qname = "q.{}.".format(self.domain_suffix.rstrip("."))
        req = DNSRecord.question(qname, qtype="TXT")
        req.header.id = random.randint(0, 65535)
        txt_parts = encode_txt_payload(payload)
        req.add_ar(RR(rname=("payload." + self.domain_suffix + "."), rtype=QTYPE.TXT, rclass=CLASS.IN, ttl=0, rdata=TXT(txt_parts)))
        packet = req.pack()

        with self.io_lock:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout_s)
            try:
                sock.sendto(packet, (self.server_host, self.server_port))
                data, _ = sock.recvfrom(8192)
            except socket.timeout:
                return {"ok": False, "error": "request timed out"}
            finally:
                sock.close()

        resp = DNSRecord.parse(data)
        if not resp.rr:
            return {"ok": False, "error": "empty response"}
        txt_parts = [part.decode("utf-8") if isinstance(part, bytes) else str(part) for part in resp.rr[0].rdata.data]
        return decode_txt_payload(txt_parts)

    def _request_retry(
        self,
        payload: dict,
        attempts: int = 4,
        backoff_s: float = 0.35,
        timeout_s: float = 2.0,
    ) -> dict:
        last: dict = {"ok": False, "error": "request timed out"}
        for i in range(attempts):
            result = self._request(payload, timeout_s=timeout_s)
            if result.get("ok"):
                return result
            last = result
            if str(result.get("error", "")) != "request timed out":
                return result
            if i < attempts - 1:
                time.sleep(backoff_s * (i + 1))
        return last

    def register(self, username: str) -> dict:
        return {"ok": False, "error": "chat secret required; use register_with_secret"}

    def register_with_secret(self, username: str, secret: str, admin_code: str = "") -> dict:
        payload = {"cmd": "register", "user": username, "secret": secret}
        if admin_code:
            payload["admin_code"] = admin_code
        result = self._request(payload)
        if result.get("ok"):
            self.token = result["token"]
            self.username = username
            self.is_admin = bool(result.get("is_admin"))
        return result

    def _authed_payload(self, payload: dict) -> dict:
        if not self.token:
            return payload
        p = dict(payload)
        p["token"] = self.token
        p["ts_ms"] = now_ms()
        p["nonce"] = uuid.uuid4().hex
        p["mac"] = sign_payload(p, self.token)
        return p

    def send_message(self, text: str) -> dict:
        if not self.token:
            return {"ok": False, "error": "not logged in"}
        with self.poll_paused():
            # Fast path for short messages: smaller payload than chunked mode.
            if len(text) <= MAX_CHAT_CHUNK_LEN:
                return self._request_retry(
                    self._authed_payload({"cmd": "send_text", "text": text}),
                    attempts=6,
                    backoff_s=0.25,
                    timeout_s=3.5,
                )
            chunks = split_text_chunks(text, MAX_CHAT_CHUNK_LEN)
            msg_id = uuid.uuid4().hex
            last_result: dict = {"ok": True}
            for idx, chunk in enumerate(chunks):
                result = self._request_retry(
                    self._authed_payload(
                        {
                            "cmd": "send_chunk",
                            "msg_id": msg_id,
                            "chunk_idx": idx,
                            "chunk_total": len(chunks),
                            "chunk_text": chunk,
                        }
                    ),
                    attempts=6,
                    backoff_s=0.25,
                    timeout_s=3.5,
                )
                if not result.get("ok"):
                    return result
                last_result = result
            return last_result

    def send_private(self, to_user: str, text: str) -> dict:
        if not self.token:
            return {"ok": False, "error": "not logged in"}
        if len(text) > 4000:
            return {"ok": False, "error": "private message too long (max 4000 chars)"}
        with self.poll_paused():
            return self._request_retry(
                self._authed_payload({"cmd": "private_send", "to_user": to_user, "text": text}),
                attempts=5,
                backoff_s=0.25,
                timeout_s=3.5,
            )

    def poll(self) -> dict:
        if not self.token:
            return {"ok": False, "error": "not logged in"}
        return self._request(self._authed_payload({"cmd": "poll"}))

    def list_users(self) -> dict:
        if not self.token:
            return {"ok": False, "error": "not logged in"}
        return self._request(self._authed_payload({"cmd": "list_users"}))

    def admin_ban(self, target: str) -> dict:
        if not self.token:
            return {"ok": False, "error": "not logged in"}
        return self._request(self._authed_payload({"cmd": "admin_ban", "target": target}))

    def admin_remove(self, target: str) -> dict:
        if not self.token:
            return {"ok": False, "error": "not logged in"}
        return self._request(self._authed_payload({"cmd": "admin_remove", "target": target}))

    def admin_unban(self, target: str) -> dict:
        if not self.token:
            return {"ok": False, "error": "not logged in"}
        return self._request(self._authed_payload({"cmd": "admin_unban", "target": target}))

    def send_file(self, file_path: str, to_user: str = "") -> dict:
        if not self.token:
            return {"ok": False, "error": "not logged in"}
        if not os.path.exists(file_path):
            return {"ok": False, "error": "file not found"}
        size = os.path.getsize(file_path)
        if size <= 0 or size > MAX_FILE_BYTES:
            return {"ok": False, "error": "file must be 1..{} bytes".format(MAX_FILE_BYTES)}
        with open(file_path, "rb") as f:
            raw = f.read()
        file_id = uuid.uuid4().hex
        filename = os.path.basename(file_path)
        sha256_hex = hashlib.sha256(raw).hexdigest()
        b64 = base64.b64encode(raw).decode("ascii")
        chunks = split_text_chunks(b64, FILE_CHUNK_B64_LEN)

        with self.poll_paused():
            start = self._request_retry(
                self._authed_payload(
                    {
                        "cmd": "file_start",
                        "file_id": file_id,
                        "filename": filename,
                        "size": size,
                        "sha256": sha256_hex,
                        "total_chunks": len(chunks),
                        "to_user": to_user,
                    }
                ),
                attempts=6,
                backoff_s=0.4,
            )
            if not start.get("ok"):
                return start
            last = {"ok": True, "file_id": file_id}
            for idx, chunk in enumerate(chunks):
                result = self._request_retry(
                    self._authed_payload({"cmd": "file_chunk", "file_id": file_id, "chunk_idx": idx, "chunk_b64": chunk}),
                    attempts=5,
                    backoff_s=0.25,
                )
                if not result.get("ok"):
                    return result
                if idx > 0 and idx % 40 == 0:
                    print(color("[Info] Upload progress: {}/{} chunks".format(idx, len(chunks)), C.DIM))
                last = result
            last["file_id"] = file_id
            last["filename"] = filename
            last["size"] = size
            return last

    def fetch_file_data_b64(self, file_id: str, chunk_b64_size: int = 80) -> dict:
        if not self.token:
            return {"ok": False, "error": "not logged in"}
        with self.poll_paused():
            pieces: list[str] = []
            idx = 0
            total = None
            while True:
                result = self._request_retry(
                    self._authed_payload({"cmd": "file_fetch_chunk", "file_id": file_id, "chunk_idx": idx, "chunk_b64_size": chunk_b64_size}),
                    attempts=12,
                    backoff_s=0.25,
                    timeout_s=3.5,
                )
                if not result.get("ok"):
                    return result
                if total is None:
                    total = int(result.get("total_chunks", 0))
                    if total <= 0:
                        return {"ok": False, "error": "invalid total_chunks"}
                pieces.append(str(result.get("chunk_b64", "")))
                idx += 1
                if idx >= total:
                    break
            return {"ok": True, "data_b64": "".join(pieces)}

    @contextmanager
    def poll_paused(self):
        self.pause_poll.set()
        try:
            # Let current poll iteration finish before starting critical request.
            time.sleep(0.05)
            yield
        finally:
            self.pause_poll.clear()


def _ask(prompt: str, default: Optional[str] = None) -> str:
    suffix = " [{}]".format(default) if default else ""
    label = color(prompt, C.CYAN)
    value = input("{}{}: ".format(label, suffix)).strip()
    return value or (default or "")


def _ask_secret(prompt: str) -> str:
    label = color(prompt, C.CYAN)
    try:
        return getpass.getpass("{}: ".format(label)).strip()
    except Exception:
        # Fallback for terminals that may not support hidden input.
        return input("{}: ".format(label)).strip()


def _enable_command_autocomplete(commands: list[str]) -> None:
    if readline is None:
        return

    def completer(text: str, state: int):
        # Complete only the command token (first token in line).
        try:
            buf = readline.get_line_buffer()
        except Exception:
            buf = text
        if " " in buf:
            return None
        options = [cmd for cmd in commands if cmd.startswith(buf or text)]
        if state < len(options):
            return options[state]
        return None

    try:
        readline.set_completer_delims(" \t\n")
        readline.set_completer(completer)
        # GNU readline
        readline.parse_and_bind("tab: complete")
        # macOS libedit readline compatibility
        readline.parse_and_bind("bind ^I rl_complete")
    except Exception:
        # Ignore terminal-specific readline failures.
        return


def main_classic() -> None:
    print(color("[Info] DNS UDP Chat CLI", C.BOLD + C.MAGENTA))
    host = _ask("Server IP", "164.92.69.93")
    port = int(_ask("Port", "53"))
    username = ""
    chat_secret = ""
    while not username:
        username = _ask("Username")
        if not username:
            print("Username is required.")
    while not chat_secret:
        chat_secret = _ask("Chat secret")
        if not chat_secret:
            print("Chat secret is required.")
    admin_code = ""
    if username == "auxgrep":
        admin_code = _ask_secret("Admin password")

    client = DNSChatClient(host, port)
    register = client.register_with_secret(username, chat_secret, admin_code=admin_code)
    if not register.get("ok"):
        print(color("[Error] Register failed: {}".format(register.get("error", "register failed")), C.RED))
        return

    print(color("[Info] Connected as {} (secret matched routing enabled)".format(username), C.GREEN))
    online_users = register.get("online_users", [])
    offline_users = register.get("offline_users", [])
    print(color("[Info] Online: {}".format(", ".join(online_users) if online_users else "(none)"), C.GREEN))
    print(color("[Info] Offline: {}".format(", ".join(offline_users) if offline_users else "(none)"), C.YELLOW))
    print(color("[Info] Commands: direct text, /users, /w <user> <msg>, /sendfile <path>, /sendfileto <user> <path>, /files, /savefile <id> <path>, /clear, /quit", C.DIM))
    if client.is_admin:
        print(color("[Info] Admin commands: /ban <user>, /unban <user> (or /unb), /remove <user>", C.DIM))
    base_commands = ["/users", "/user", "/w", "/sendfile", "/sendfileto", "/files", "/savefile", "/msg", "/clear", "/quit"]
    admin_commands = ["/ban", "/unban", "/unb", "/remove"]
    _enable_command_autocomplete(base_commands + (admin_commands if client.is_admin else []))
    if readline is None:
        print(color("[Info] Tab autocomplete is limited on this terminal. Install pyreadline3 on Windows.", C.DIM))

    running = True
    print_lock = threading.Lock()
    prompt_text = color("[chat_mode] > ", C.BOLD + C.MAGENTA)

    def _restore_prompt() -> None:
        # Repaint prompt after async inbox/system output.
        try:
            sys.stdout.write(prompt_text)
            sys.stdout.flush()
        except Exception:
            pass

    def poll_loop() -> None:
        timeout_streak = 0
        poll_interval = 1.2
        max_interval = 8.0
        while running:
            try:
                if client.pause_poll.is_set():
                    time.sleep(0.15)
                    continue
                result = client.poll()
                if result.get("ok"):
                    if timeout_streak >= 3:
                        with print_lock:
                            print("\n" + color("[Info] Poll recovered.", C.GREEN))
                            _restore_prompt()
                    timeout_streak = 0
                    poll_interval = 1.2
                    for msg in result.get("messages", []):
                        rendered = msg["text"]
                        # Highlight @mentions for this user in local terminal.
                        mention = "@{}".format(username)
                        if mention.lower() in rendered.lower():
                            rendered = color(rendered, C.YELLOW)
                        if msg["from_user"] == "[system]":
                            rendered = color(rendered, C.BLUE)
                        with print_lock:
                            print(
                                "\n{} {} {}".format(
                                    color("[inbox]", C.YELLOW),
                                    color("{} -> me:".format(msg["from_user"]), C.CYAN),
                                    rendered,
                                )
                            )
                            _restore_prompt()
                    for f in result.get("files", []):
                        file_id = str(f.get("file_id", ""))
                        if file_id:
                            client.received_files[file_id] = f
                            with print_lock:
                                print(
                                    "\n{} {} {} {}".format(
                                        color("[file]", C.MAGENTA),
                                        color("{} -> me:".format(f.get("from_user", "?")), C.CYAN),
                                        f.get("filename", "unknown"),
                                        color("(id={} size={}B)".format(file_id, f.get("size", 0)), C.DIM),
                                    )
                                )
                                _restore_prompt()
                else:
                    err = str(result.get("error", "unknown error"))
                    if err == "request timed out":
                        timeout_streak += 1
                        # Fully silent timeout handling: backoff with no terminal noise.
                        poll_interval = min(max_interval, poll_interval * 1.35)
                    else:
                        timeout_streak = 0
                        poll_interval = 1.5
                        # Keep poll transport noise hidden; chat events remain visible.
            except Exception as exc:
                timeout_streak = 0
                poll_interval = 1.5
                # Keep poll exception noise hidden; chat events remain visible.
            time.sleep(poll_interval)

    t = threading.Thread(target=poll_loop, daemon=True)
    t.start()

    try:
        while True:
            line = input(prompt_text)
            if not line.strip():
                continue
            if line.strip() == "/quit":
                break
            if line.strip() == "/clear":
                # ANSI clear screen + cursor home.
                print("\033[2J\033[H", end="")
                print(color("[Info] Chat view cleared.", C.DIM))
                continue
            if line.strip() in ("/users", "/user"):
                users_result = client.list_users()
                if users_result.get("ok"):
                    online_users = users_result.get("online_users", [])
                    offline_users = users_result.get("offline_users", [])
                    print(color("Online: {}".format(", ".join(online_users) if online_users else "(none)"), C.GREEN))
                    print(color("Offline: {}".format(", ".join(offline_users) if offline_users else "(none)"), C.YELLOW))
                else:
                    print(color("List users failed: {}".format(users_result.get("error", "unknown error")), C.RED))
                continue
            if line.strip().startswith("/w "):
                _, _, rest = line.strip().partition(" ")
                to_user, _, ptext = rest.partition(" ")
                if not to_user or not ptext.strip():
                    print(color("Use: /w <user> <message>", C.YELLOW))
                    continue
                result = client.send_private(to_user, ptext.strip())
                if result.get("ok"):
                    print("{} {} {}".format(color("[private]", C.MAGENTA), color("me -> {}:".format(to_user), C.CYAN), ptext.strip()))
                else:
                    print(color("Private send failed: {}".format(result.get("error", "unknown error")), C.RED))
                continue
            if line.strip().startswith("/sendfile "):
                path = line.strip()[10:].strip()
                if not path:
                    print(color("Use: /sendfile <path>", C.YELLOW))
                    continue
                result = client.send_file(path)
                if result.get("ok"):
                    print(
                        "{} {} {}".format(
                            color("[file-sent]", C.GREEN),
                            result.get("filename", ""),
                            color("(id={} delivered_to={})".format(result.get("file_id", "?"), result.get("delivered_to", "?")), C.DIM),
                        )
                    )
                else:
                    print(color("File send failed: {}".format(result.get("error", "unknown error")), C.RED))
                continue
            if line.strip().startswith("/sendfileto "):
                rest = line.strip()[12:].strip()
                to_user, _, path = rest.partition(" ")
                if not to_user or not path.strip():
                    print(color("Use: /sendfileto <user> <path>", C.YELLOW))
                    continue
                result = client.send_file(path.strip(), to_user=to_user.strip())
                if result.get("ok"):
                    print(
                        "{} {} {} {}".format(
                            color("[file-sent]", C.GREEN),
                            result.get("filename", ""),
                            color("to {}".format(to_user.strip()), C.CYAN),
                            color("(id={} delivered_to={})".format(result.get("file_id", "?"), result.get("delivered_to", "?")), C.DIM),
                        )
                    )
                else:
                    print(color("Private file send failed: {}".format(result.get("error", "unknown error")), C.RED))
                continue
            if line.strip() == "/files":
                if not client.received_files:
                    print(color("No received files.", C.YELLOW))
                else:
                    for fid, finfo in client.received_files.items():
                        print(
                            "{} {} {} {}".format(
                                color("[file]", C.MAGENTA),
                                fid,
                                finfo.get("filename", "unknown"),
                                color("({} bytes)".format(finfo.get("size", 0)), C.DIM),
                            )
                        )
                continue
            if line.strip().startswith("/savefile "):
                rest = line.strip()[10:].strip()
                fid, _, out_path = rest.partition(" ")
                if not fid or not out_path.strip():
                    print(color("Use: /savefile <file_id> <output_path>", C.YELLOW))
                    continue
                finfo = client.received_files.get(fid)
                if not finfo:
                    print(color("Unknown file_id. Use /files", C.RED))
                    continue
                try:
                    fetched = client.fetch_file_data_b64(fid)
                    if not fetched.get("ok"):
                        print(color("Fetch failed: {}".format(fetched.get("error", "unknown error")), C.RED))
                        continue
                    raw = base64.b64decode(str(fetched.get("data_b64", "")).encode("ascii"), validate=True)
                    target = out_path.strip()
                    if os.path.isdir(target):
                        target = os.path.join(target, str(finfo.get("filename", fid)))
                    with open(target, "wb") as f:
                        f.write(raw)
                    digest = hashlib.sha256(raw).hexdigest().lower()
                    if digest != str(finfo.get("sha256", "")).lower():
                        print(color("Saved but checksum mismatch!", C.RED))
                    else:
                        print(color("Saved file to {}".format(target), C.GREEN))
                except Exception as exc:
                    print(color("Save failed: {}".format(str(exc)), C.RED))
                continue
            if line.strip().startswith("/ban "):
                target = line.strip()[5:].strip()
                if not target:
                    print(color("Use: /ban <user>", C.YELLOW))
                    continue
                result = client.admin_ban(target)
                if result.get("ok"):
                    print(color("User banned: {}".format(target), C.YELLOW))
                else:
                    print(color("Ban failed: {}".format(result.get("error", "unknown error")), C.RED))
                continue
            if line.strip().startswith("/remove "):
                target = line.strip()[8:].strip()
                if not target:
                    print(color("Use: /remove <user>", C.YELLOW))
                    continue
                result = client.admin_remove(target)
                if result.get("ok"):
                    print(color("User removed: {}".format(target), C.YELLOW))
                else:
                    print(color("Remove failed: {}".format(result.get("error", "unknown error")), C.RED))
                continue
            if line.strip().startswith("/unban ") or line.strip().startswith("/unb "):
                if line.strip().startswith("/unban "):
                    target = line.strip()[7:].strip()
                else:
                    target = line.strip()[5:].strip()
                if not target:
                    print(color("Use: /unban <user>", C.YELLOW))
                    continue
                result = client.admin_unban(target)
                if result.get("ok"):
                    print(color("User unbanned: {}".format(target), C.YELLOW))
                else:
                    print(color("Unban failed: {}".format(result.get("error", "unknown error")), C.RED))
                continue
            if line.strip().startswith("/msg "):
                _, _, msg_text = line.partition(" ")
                if not msg_text.strip():
                    print(color("Use: /msg <message>", C.YELLOW))
                    continue
                text = msg_text.strip()
            elif line.strip().startswith("/"):
                print(color("Unknown command. Use /users, /w, /sendfile, /sendfileto, /files, /savefile, /ban, /unban, /remove, /quit", C.YELLOW))
                continue
            else:
                # Convenience mode: plain text is treated as chat message.
                text = line
            try:
                result = client.send_message(text)
                if result.get("ok"):
                    print(
                        "{} {} {}".format(
                            color("[sent]", C.GREEN),
                            color("me(secret) -> peers:", C.CYAN),
                            "{} {}".format(text, color("(delivered_to={})".format(result.get("delivered_to", "?")), C.DIM)),
                        )
                    )
                else:
                    print(color("[Error] Send failed: {}".format(result.get("error", "unknown error")), C.RED))
            except Exception as exc:
                print(color("[Error] Send exception: {}".format(str(exc)), C.RED))
    except KeyboardInterrupt:
        pass
    finally:
        running = False
        print(color("[Info] Bye.", C.DIM))


if __name__ == "__main__":
    main_classic()
