from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from .constants import DataClass

@dataclass(frozen=True)
class ToolSchema:
    name: str
    allowed_params: List[str]
    required_params: List[str]
    produces: Optional[DataClass] = None
    consumes: Optional[DataClass] = None

TOOL_REGISTRY: Dict[str, ToolSchema] = {
    "upload_file": ToolSchema(
        name="upload_file",
        allowed_params=["source", "destination", "file_size", "data_class", "jurisdiction"],
        required_params=["source", "destination"],
        consumes=DataClass.CONFIDENTIAL
    ),
    "read_slack_history": ToolSchema(
        name="read_slack_history",
        allowed_params=["channel", "search", "date_from", "date_to", "data_class"],
        required_params=["channel"],
        consumes=DataClass.INTERNAL
    ),
    "edit_system_prompt": ToolSchema(
        name="edit_system_prompt",
        allowed_params=["new_prompt", "reason"],
        required_params=["new_prompt"],
        consumes=DataClass.INTERNAL
    )
}
