from dataclasses import dataclass
from typing import Dict, Optional
from .constants import DataClass

@dataclass(frozen=True)
class Actor:
    id: str
    display: str
    org_unit: str
    role: str

@dataclass(frozen=True)
class Intent:
    statement: str
    purpose: str
    business_process: str
    ticket_id: Optional[str] = None

@dataclass(frozen=True)
class ExecutionContext:
    actor: Actor
    agent_id: str
    session_id: str
    intent: Intent
    environment: str
    jurisdiction: str
    data_class: DataClass
    attributes: Dict[str, str]
