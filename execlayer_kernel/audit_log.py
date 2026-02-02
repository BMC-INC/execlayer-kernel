import json
from dataclasses import dataclass
from typing import Any, Dict, Optional
from .crypto import canonical_json, link_hash, sha256_hex

@dataclass
class AuditState:
    prev_entry_hash: Optional[str] = None

class AppendOnlyAuditLog:
    def __init__(self, path: str):
        self.path = path
        self.state = AuditState()

    def append(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        payload = canonical_json(entry)
        payload_hash = sha256_hex(payload)
        entry_hash = link_hash(self.state.prev_entry_hash, payload_hash)

        wrapped = {
            "payload": entry,
            "payload_hash": f"sha256:{payload_hash}",
            "entry_hash": f"sha256:{entry_hash}",
            "prev_entry_hash": f"sha256:{self.state.prev_entry_hash}" if self.state.prev_entry_hash else None
        }

        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps(wrapped, ensure_ascii=False) + "\n")

        self.state.prev_entry_hash = entry_hash
        return wrapped
