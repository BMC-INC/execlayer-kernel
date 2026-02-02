import base64
import hashlib
import hmac
import json
from typing import Any, Dict, Optional

def canonical_json(obj: Dict[str, Any]) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

def sha256_hex(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()

def hmac_sign(secret: bytes, message: str) -> str:
    sig = hmac.new(secret, message.encode("utf-8"), hashlib.sha256).digest()
    return base64.b64encode(sig).decode("utf-8")

def link_hash(prev_hash: Optional[str], payload_hash: str) -> str:
    base = (prev_hash or "") + ":" + payload_hash
    return sha256_hex(base)
