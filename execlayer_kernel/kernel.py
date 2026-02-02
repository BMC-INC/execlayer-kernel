import time
import uuid
from typing import Any, Dict, Optional

from .audit_log import AppendOnlyAuditLog
from .constants import Verdict, RiskTier
from .policy_bundle import PolicyBundle, PolicyOutcome
from .receipts import attach_governance, build_receipt_base, sign_receipt
from .validation import validate_tool_call

class ExecLayerKernel:
    def __init__(
        self,
        policy_bundle: PolicyBundle,
        audit_log_path: str = "execlayer_audit.log.jsonl",
        signing_secret: bytes = b"dev_secret_change_me",
        mode: str = "demo"
    ):
        self.policy_bundle = policy_bundle
        self.audit_log = AppendOnlyAuditLog(audit_log_path)
        self.signing_secret = signing_secret
        self.mode = mode

    def intercept(self, ctx, tool_call: Dict[str, Any]) -> Dict[str, Any]:
        start = time.time()

        try:
            validate_tool_call(tool_call)
        except Exception as e:
            return self._create_error_receipt(ctx, tool_call, str(e), start)

        tool_name = tool_call["function"]
        params = tool_call["parameters"]

        ctx = self._stamp_policy_bundle(ctx)

        if self.mode == "demo":
            ctx = self._annotate_demo_mode(ctx)

        outcome = self._evaluate(ctx, tool_name, params)

        latency_ms = int((time.time() - start) * 1000)

        if outcome is None:
            result = {
                "status": Verdict.ALLOW.value,
                "mode": self.mode,
                "output": "Mock execution succeeded (demo mode)." if self.mode == "demo" else "Execution authorized."
            }
            self.audit_log.append({
                "event": "ALLOW",
                "session_id": ctx.session_id,
                "agent_id": ctx.agent_id,
                "tool": tool_name,
                "latency_ms": latency_ms
            })
            return result

        receipt = build_receipt_base(ctx, tool_name, params)
        attach_governance(receipt, outcome, latency_ms)

        if outcome.verdict == Verdict.BLOCK:
            receipt["enforcement"] = {
                "action": "TERMINATED_AT_KERNEL_BOUNDARY",
                "mode": self.mode
            }
        else:
            receipt["enforcement"] = {
                "action": "ESCALATED_FOR_HUMAN_APPROVAL",
                "approval_id": self._mint_approval_id(),
                "mode": self.mode
            }

        if self.mode == "demo":
            receipt["disclaimer"] = "This is a demonstration. In production, this would block actual tool execution."

        sign_receipt(receipt, self.signing_secret)

        wrapped = self.audit_log.append({
            "event": outcome.verdict.value,
            "receipt": receipt
        })

        receipt["audit"] = {
            "entry_hash": wrapped["entry_hash"],
            "prev_entry_hash": wrapped["prev_entry_hash"],
            "storage_note": "Forensic artifact written to ephemeral store. Configure durable storage for production."
        }
        return receipt

    def _create_error_receipt(self, ctx, tool_call, error_msg, start_time):
        latency_ms = int((time.time() - start_time) * 1000)
        receipt = build_receipt_base(ctx, tool_call.get("function", "unknown"), tool_call.get("parameters", {}))
        receipt["verdict"] = {
            "status": "ERROR",
            "latency_ms": latency_ms,
            "error": error_msg,
            "note": "Kernel encountered an error during evaluation"
        }
        receipt["enforcement"] = {"action": "BLOCKED_DUE_TO_ERROR"}
        return receipt

    def _mint_approval_id(self) -> str:
        return "appr_" + uuid.uuid4().hex[:10]

    def _stamp_policy_bundle(self, ctx):
        attrs = dict(ctx.attributes)
        attrs["policy_bundle_id"] = self.policy_bundle.bundle_id
        attrs["policy_bundle_version"] = self.policy_bundle.version
        return type(ctx)(
            actor=ctx.actor,
            agent_id=ctx.agent_id,
            session_id=ctx.session_id,
            intent=ctx.intent,
            environment=ctx.environment,
            jurisdiction=ctx.jurisdiction,
            data_class=ctx.data_class,
            attributes=attrs
        )

    def _annotate_demo_mode(self, ctx):
        attrs = dict(ctx.attributes)
        attrs["execution_mode"] = "DEMO"
        return type(ctx)(
            actor=ctx.actor,
            agent_id=ctx.agent_id,
            session_id=ctx.session_id,
            intent=ctx.intent,
            environment=ctx.environment,
            jurisdiction=ctx.jurisdiction,
            data_class=ctx.data_class,
            attributes=attrs
        )

    def _evaluate(self, ctx, tool_name: str, params: Dict[str, Any]) -> Optional[PolicyOutcome]:
        rules = sorted(self.policy_bundle.rules, key=lambda r: r.priority, reverse=True)
        for rule in rules:
            outcome = rule.evaluate(ctx, tool_name, params)
            if outcome:
                return outcome
        return None
