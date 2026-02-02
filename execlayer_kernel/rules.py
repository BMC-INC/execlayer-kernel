from typing import Any, Dict, Optional
from .constants import DataClass, RiskTier, Verdict
from .policy_bundle import PolicyOutcome, PolicyRule

def _is_public_destination(dest: str) -> bool:
    d = (dest or "").lower()
    return ("public" in d) or ("://" in d and "internal" not in d and "private" not in d)

def _looks_like_secret_search(term: str) -> bool:
    t = (term or "").lower()
    needles = ["api_key", "apikey", "secret", "token", "oauth", "password", "sig", "private_key"]
    return any(n in t for n in needles)

class RuleBlockPublicPIIUpload(PolicyRule):
    def evaluate(self, ctx, tool_name: str, params: Dict[str, Any]) -> Optional[PolicyOutcome]:
        if tool_name != "upload_file":
            return None
        data_class = params.get("data_class") or ctx.data_class.value
        dest = params.get("destination", "")
        if str(data_class).upper() in [DataClass.PII.value, DataClass.PHI.value, DataClass.PCI.value] and _is_public_destination(dest):
            return PolicyOutcome(
                verdict=Verdict.BLOCK,
                risk_tier=RiskTier.CRITICAL,
                risk_score=9.6,
                violation_key="DATA_SOVEREIGNTY",
                reason="Attempted transfer of regulated data to non-compliant destination.",
                rule_id=self.rule_id
            )
        return None

class RuleEscalateCrossBorderSensitiveUpload(PolicyRule):
    def evaluate(self, ctx, tool_name: str, params: Dict[str, Any]) -> Optional[PolicyOutcome]:
        if tool_name != "upload_file":
            return None
        data_class = params.get("data_class") or ctx.data_class.value
        dest_juris = params.get("jurisdiction")
        if str(data_class).upper() in [DataClass.CONFIDENTIAL.value, DataClass.PII.value, DataClass.PHI.value]:
            if dest_juris and dest_juris != ctx.jurisdiction:
                return PolicyOutcome(
                    verdict=Verdict.ESCALATE,
                    risk_tier=RiskTier.HIGH,
                    risk_score=8.1,
                    violation_key="DATA_SOVEREIGNTY",
                    reason="Cross-jurisdiction data movement requires explicit approval and retention constraints.",
                    rule_id=self.rule_id
                )
        return None

class RuleBlockSlackSecretScrape(PolicyRule):
    def evaluate(self, ctx, tool_name: str, params: Dict[str, Any]) -> Optional[PolicyOutcome]:
        if tool_name != "read_slack_history":
            return None
        search = params.get("search", "")
        if _looks_like_secret_search(search):
            return PolicyOutcome(
                verdict=Verdict.BLOCK,
                risk_tier=RiskTier.HIGH,
                risk_score=8.7,
                violation_key="SHADOW_AI",
                reason="Attempted credential harvesting from message history.",
                rule_id=self.rule_id
            )
        return None

class RuleBlockSelfPromptRewrite(PolicyRule):
    def evaluate(self, ctx, tool_name: str, params: Dict[str, Any]) -> Optional[PolicyOutcome]:
        if tool_name != "edit_system_prompt":
            return None
        return PolicyOutcome(
            verdict=Verdict.BLOCK,
            risk_tier=RiskTier.CRITICAL,
            risk_score=9.9,
            violation_key="AGENTIC_ARCH",
            reason="Attempted modification of governance constraints.",
            rule_id=self.rule_id
        )
