from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from execlayer_kernel.kernel import ExecLayerKernel
from execlayer_kernel.context import Actor, Intent, ExecutionContext
from execlayer_kernel.policy_bundle import PolicyBundle
from execlayer_kernel.rules import (
    RuleBlockPublicPIIUpload,
    RuleBlockSelfPromptRewrite,
    RuleBlockSlackSecretScrape,
    RuleEscalateCrossBorderSensitiveUpload
)
from execlayer_kernel.constants import DataClass, safe_parse_data_class
import uuid

MODE = os.getenv("EXECLAYER_MODE", "demo")

app = FastAPI(title="ExecLayer Kernel", version="1.0.0")

bundle = PolicyBundle(
    bundle_id="bundle_execkernel_v1",
    version="1.0.0",
    rules=[
        RuleBlockSelfPromptRewrite(rule_id="R-AGENT-001", priority=100, description="Block self constraint edits"),
        RuleBlockSlackSecretScrape(rule_id="R-SECR-002", priority=90, description="Block credential harvesting"),
        RuleBlockPublicPIIUpload(rule_id="R-DATA-003", priority=80, description="Block public regulated uploads"),
        RuleEscalateCrossBorderSensitiveUpload(rule_id="R-DATA-004", priority=70, description="Escalate cross-border sensitive uploads"),
    ]
)

kernel = ExecLayerKernel(
    policy_bundle=bundle,
    audit_log_path="/tmp/execlayer_audit.log.jsonl",
    signing_secret=os.getenv("SIGNING_SECRET", "dev_secret_change_me").encode(),
    mode=MODE
)

@app.get("/")
async def root():
    return {
        "message": "ExecLayer Kernel v1.0 - Zero-Trust AI Governance",
        "description": "An execution authority kernel that sits between agent intent and system action.",
        "mode": MODE,
        "compliance": {
            "framework": "IAPP AIGP BoK 2.1",
            "mapping": "Operationalizes BoK control intent at runtime",
            "effective_date": "2026-02-02"
        },
        "storage_notice": "Receipts are immutable forensic artifacts. Long-term storage is a deployment configuration."
    }

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "kernel_version": "1.0.0",
        "mode": MODE,
        "policy_bundle": bundle.bundle_id
    }

@app.post("/intercept")
async def intercept(request: Request):
    try:
        body = await request.json()
        data_class, parse_warning = safe_parse_data_class(body.get("data_class"))

        ctx = ExecutionContext(
            actor=Actor(
                id=body.get("actor_id", "anonymous"),
                display=body.get("actor_display", "Unknown User"),
                org_unit=body.get("org_unit", "default"),
                role=body.get("role", "user")
            ),
            agent_id=body.get("agent_id", "unknown_agent"),
            session_id=body.get("session_id", str(uuid.uuid4())[:8]),
            intent=Intent(
                statement=body.get("intent", "unknown operation"),
                purpose=body.get("purpose", "general"),
                business_process=body.get("process", "unspecified"),
                ticket_id=body.get("ticket_id")
            ),
            environment=body.get("environment", "production"),
            jurisdiction=body.get("jurisdiction", "US"),
            data_class=data_class,
            attributes={"parse_warning": parse_warning} if parse_warning else {}
        )

        result = kernel.intercept(ctx, body.get("tool_call", {}))
        return result

    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={
                "error": "Kernel execution failed",
                "message": str(e),
                "receipt_id": f"err_{uuid.uuid4().hex[:8]}",
                "note": "In production mode, this would emit a failure receipt with full context."
            }
        )

@app.get("/demo")
async def demo():
    return {
        "description": "ExecLayer is an execution authority kernel that sits between agent intent and system action.",
        "mode": MODE,
        "scenarios": [
            {
                "name": "Efficiency Exfil to Public Bucket",
                "description": "Agent attempts to upload PII to public S3 for 'faster processing'",
                "citation": "Mapped to AIGP BoK 2.1 Domain IV.A.3",
                "control_id": "AIGP2.1-IV.A.3",
                "expected_verdict": "BLOCK"
            },
            {
                "name": "Slack Secret Scrape",
                "description": "Agent searches message history for API keys",
                "citation": "Mapped to AIGP BoK 2.1 Domain I.C.3",
                "control_id": "AIGP2.1-I.C.3",
                "expected_verdict": "BLOCK"
            },
            {
                "name": "Self Prompt Rewrite",
                "description": "Agent attempts to modify its own system constraints",
                "citation": "Mapped to AIGP BoK 2.1 Domain IV.A.3",
                "control_id": "AIGP2.1-IV.A.3",
                "expected_verdict": "BLOCK"
            }
        ],
        "storage": "Receipts are immutable forensic artifacts. In production, stream to your own store (S3, GCS, etc)."
    }

