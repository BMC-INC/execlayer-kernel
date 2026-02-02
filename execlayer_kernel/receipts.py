import datetime
import uuid
from typing import Any, Dict, Optional
from .bok import BOK_2_1
from .crypto import canonical_json, hmac_sign, sha256_hex

def utc_now_iso() -> str:
    return datetime.datetime.utcnow().replace(microsecond=0).isoformat() + "Z"

def mint_receipt_id(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:10]}"

def build_receipt_base(ctx, tool_name: str, params: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "receipt_id": mint_receipt_id("rcpt"),
        "timestamp_utc": utc_now_iso(),
        "kernel": {
            "name": "ExecLayerKernel",
            "kernel_version": "1.0.0",
            "policy_bundle_id": ctx.attributes.get("policy_bundle_id", "bundle_unknown"),
            "policy_bundle_version": ctx.attributes.get("policy_bundle_version", "0.0.0")
        },
        "actor": {
            "id": ctx.actor.id,
            "display": ctx.actor.display,
            "org_unit": ctx.actor.org_unit,
            "role": ctx.actor.role
        },
        "agent": {
            "agent_id": ctx.agent_id,
            "session_id": ctx.session_id,
            "environment": ctx.environment
        },
        "intent": {
            "statement": ctx.intent.statement,
            "purpose": ctx.intent.purpose,
            "business_process": ctx.intent.business_process,
            "ticket_id": ctx.intent.ticket_id
        },
        "context": {
            "jurisdiction": ctx.jurisdiction,
            "data_class": ctx.data_class.value
        },
        "intercepted": {
            "tool": tool_name,
            "parameters": params
        }
    }

def attach_governance(receipt: Dict[str, Any], outcome, latency_ms: int) -> None:
    citation = BOK_2_1.get(outcome.violation_key or "", {})
    receipt["verdict"] = {
        "status": outcome.verdict.value,
        "latency_ms": latency_ms,
        "risk": {
            "tier": outcome.risk_tier.value,
            "score": outcome.risk_score,
            "reason": outcome.reason
        },
        "policy": {
            "rule_id": outcome.rule_id,
            "violation_key": outcome.violation_key,
            "citation": citation
        }
    }

def sign_receipt(receipt: Dict[str, Any], signing_secret: bytes) -> Dict[str, Any]:
    payload = canonical_json(receipt)
    payload_hash = sha256_hex(payload)
    signature = hmac_sign(signing_secret, payload)

    receipt["crypto"] = {
        "payload_hash": f"sha256:{payload_hash}",
        "signature_type": "HMAC-SHA256",
        "signature_b64": signature
    }
    return receipt
