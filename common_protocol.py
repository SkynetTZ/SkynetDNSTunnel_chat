import base64
import hashlib
import hmac
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any, Sequence, Union


DOMAIN_SUFFIX = "microsoft.com" # CHANGE THIS TO ANY DOMAIN YOU WANT TO USE
MAX_LABEL_LEN = 50
MAX_TXT_PART_LEN = 240
MAX_CHAT_CHUNK_LEN = 180

def _b32_encode(raw: bytes) -> str:
    return base64.b32encode(raw).decode("ascii").rstrip("=").lower()


def _b32_decode(raw: str) -> bytes:
    raw = raw.upper()
    pad = "=" * ((8 - len(raw) % 8) % 8)
    return base64.b32decode(raw + pad)


def encode_query_payload(payload: dict[str, Any], domain_suffix: str = DOMAIN_SUFFIX) -> str:
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    encoded = _b32_encode(raw)
    labels = [encoded[i : i + MAX_LABEL_LEN] for i in range(0, len(encoded), MAX_LABEL_LEN)]
    labels.append(domain_suffix.rstrip("."))
    return ".".join(labels) + "."


def decode_query_payload(qname: str, domain_suffix: str = DOMAIN_SUFFIX) -> dict[str, Any]:
    qname = qname.rstrip(".").lower()
    suffix = domain_suffix.rstrip(".").lower()
    if not qname.endswith(suffix):
        raise ValueError("Query is outside the configured domain")
    head = qname[: -len(suffix)].rstrip(".")
    if not head:
        raise ValueError("Missing encoded payload labels")
    encoded = head.replace(".", "")
    raw = _b32_decode(encoded)
    return json.loads(raw.decode("utf-8"))


def split_text_chunks(raw: str, chunk_size: int) -> list[str]:
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    return [raw[i : i + chunk_size] for i in range(0, len(raw), chunk_size)] or [""]


def encode_txt_payload(payload: dict[str, Any]) -> list[str]:
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    encoded = _b32_encode(raw)
    return split_text_chunks(encoded, MAX_TXT_PART_LEN)


def decode_txt_payload(txt_payload: Union[str, Sequence[str]]) -> dict[str, Any]:
    if isinstance(txt_payload, str):
        joined = txt_payload
    else:
        joined = "".join(txt_payload)
    raw = _b32_decode(joined)
    return json.loads(raw.decode("utf-8"))


def now_ms() -> int:
    return int(time.time() * 1000)


def new_session_token() -> str:
    return secrets.token_hex(16)


def canonical_json(payload: dict[str, Any]) -> str:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True, ensure_ascii=True)


def sign_payload(payload: dict[str, Any], key: str) -> str:
    material = canonical_json(payload).encode("utf-8")
    return hmac.new(key.encode("utf-8"), material, hashlib.sha256).hexdigest()


def secret_room_id(secret: str) -> str:
    return hashlib.sha256(secret.encode("utf-8")).hexdigest()


@dataclass
class Message:
    from_user: str
    text: str
    ts_ms: int
