from enum import Enum
from typing import Tuple, Optional

class Verdict(str, Enum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    ESCALATE = "ESCALATE"

class RiskTier(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class DataClass(str, Enum):
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    PII = "PII"
    PHI = "PHI"
    PCI = "PCI"
    SECRETS = "SECRETS"

def safe_parse_data_class(value: any) -> Tuple[DataClass, Optional[str]]:
    if value is None:
        return DataClass.INTERNAL, "No data_class provided, defaulting to INTERNAL"
    try:
        str_value = str(value).upper().strip()
        return DataClass(str_value), None
    except (ValueError, KeyError):
        return DataClass.INTERNAL, f"Invalid data_class '{value}', defaulting to INTERNAL"
