from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from .constants import RiskTier, Verdict

@dataclass(frozen=True)
class PolicyOutcome:
    verdict: Verdict
    risk_tier: RiskTier
    risk_score: float
    violation_key: Optional[str]
    reason: str
    rule_id: str

@dataclass(frozen=True)
class PolicyRule:
    rule_id: str
    priority: int
    description: str

    def evaluate(self, ctx, tool_name: str, params: Dict[str, Any]) -> Optional[PolicyOutcome]:
        raise NotImplementedError

@dataclass(frozen=True)
class PolicyBundle:
    bundle_id: str
    version: str
    rules: List[PolicyRule]
