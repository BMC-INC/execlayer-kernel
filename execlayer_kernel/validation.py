from typing import Any, Dict
from .schemas import TOOL_REGISTRY

class ValidationError(Exception):
    pass

def validate_tool_call(tool_call: Dict[str, Any]) -> None:
    if "function" not in tool_call or "parameters" not in tool_call:
        raise ValidationError("Tool call missing required keys: function, parameters")

    fn = tool_call["function"]
    params = tool_call["parameters"]

    if fn not in TOOL_REGISTRY:
        raise ValidationError(f"Unknown tool: {fn}")

    schema = TOOL_REGISTRY[fn]

    if not isinstance(params, dict):
        raise ValidationError("parameters must be an object")

    for req in schema.required_params:
        if req not in params:
            raise ValidationError(f"Missing required parameter: {req}")

    for key in params.keys():
        if key not in schema.allowed_params:
            raise ValidationError(f"Disallowed parameter: {key}")
