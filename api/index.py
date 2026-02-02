from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from openai import OpenAI

import os
import sys
import uuid

# Make execlayer_kernel importable
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from execlayer_kernel.kernel import ExecLayerKernel
from execlayer_kernel.context import Actor, Intent, ExecutionContext
from execlayer_kernel.policy_bundle import PolicyBundle
from execlayer_kernel.rules import (
    RuleBlockPublicPIIUpload,
    RuleBlockSelfPromptRewrite,
    RuleBlockSlackSecretScrape,
    RuleEscalateCrossBorderSensitiveUpload,
)
from execlayer_kernel.constants import DataClass, safe_parse_data_class


MODE = os.getenv("EXECLAYER_MODE", "demo")

# --- FastAPI app setup -------------------------------------------------------

app = FastAPI(title="ExecLayer Kernel", version="1.0.0")

# CORS so the /ui page (or other frontends) can call /agent from a browser
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- ExecLayer kernel setup --------------------------------------------------

bundle = PolicyBundle(
    bundle_id="bundle_execkernel_v1",
    version="1.0.0",
    rules=[
        RuleBlockSelfPromptRewrite(
            rule_id="R-AGENT-001", priority=100, description="Block self constraint edits"
        ),
        RuleBlockSlackSecretScrape(
            rule_id="R-SECR-002", priority=90, description="Block credential harvesting"
        ),
        RuleBlockPublicPIIUpload(
            rule_id="R-DATA-003", priority=80, description="Block public regulated uploads"
        ),
        RuleEscalateCrossBorderSensitiveUpload(
            rule_id="R-DATA-004",
            priority=70,
            description="Escalate cross-border sensitive uploads",
        ),
    ],
)

kernel = ExecLayerKernel(
    policy_bundle=bundle,
    audit_log_path="/tmp/execlayer_audit.log.jsonl",
    signing_secret=os.getenv("SIGNING_SECRET", "dev_secret_change_me").encode(),
    mode=MODE,
)

# --- OpenAI client for the governance agent ---------------------------------

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
client = OpenAI(api_key=OPENAI_API_KEY)


class AgentRequest(BaseModel):
    question: str
    context: str | None = None


class AgentResponse(BaseModel):
    answer: str
    reasoning: str | None = None


# --- Existing routes ---------------------------------------------------------


@app.get("/")
async def root():
    return {
        "message": "ExecLayer Kernel v1.0 - Zero-Trust AI Governance",
        "description": "An execution authority kernel that sits between agent intent and system action.",
        "mode": MODE,
        "compliance": {
            "framework": "IAPP AIGP BoK 2.1",
            "mapping": "Operationalizes BoK control intent at runtime",
            "effective_date": "2026-02-02",
        },
        "storage_notice": "Receipts are immutable forensic artifacts. Long-term storage is a deployment configuration.",
    }


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "kernel_version": "1.0.0",
        "mode": MODE,
        "policy_bundle": bundle.bundle_id,
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
                role=body.get("role", "user"),
            ),
            agent_id=body.get("agent_id", "unknown_agent"),
            session_id=body.get("session_id", str(uuid.uuid4())[:8]),
            intent=Intent(
                statement=body.get("intent", "unknown operation"),
                purpose=body.get("purpose", "general"),
                business_process=body.get("process", "unspecified"),
                ticket_id=body.get("ticket_id"),
            ),
            environment=body.get("environment", "production"),
            jurisdiction=body.get("jurisdiction", "US"),
            data_class=data_class,
            attributes={"parse_warning": parse_warning} if parse_warning else {},
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
                "note": "In production mode, this would emit a failure receipt with full context.",
            },
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
                "expected_verdict": "BLOCK",
            },
            {
                "name": "Slack Secret Scrape",
                "description": "Agent searches message history for API keys",
                "citation": "Mapped to AIGP BoK 2.1 Domain I.C.3",
                "control_id": "AIGP2.1-I.C.3",
                "expected_verdict": "BLOCK",
            },
            {
                "name": "Self Prompt Rewrite",
                "description": "Agent attempts to modify its own system constraints",
                "citation": "Mapped to AIGP BoK 2.1 Domain IV.A.3",
                "control_id": "AIGP2.1-IV.A.3",
                "expected_verdict": "BLOCK",
            },
        ],
        "storage": "Receipts are immutable forensic artifacts. In production, stream to your own store (S3, GCS, etc).",
    }


# --- NEW: ExecLayer governance agent ----------------------------------------


@app.post("/agent", response_model=AgentResponse)
async def exec_layer_agent(payload: AgentRequest) -> AgentResponse:
    if not OPENAI_API_KEY:
        raise HTTPException(
            status_code=500,
            detail="OPENAI_API_KEY is not set in the environment.",
        )

    system_prompt = (
        "You are the ExecLayer Kernel AI Governance Agent. "
        "You sit between agent intent and system action. "
        "You give concrete AI governance and risk management guidance, "
        "grounded in zero‑trust, execution‑layer controls, receipts/forensics, "
        "and mappings to frameworks like IAPP AIGP BoK 2.1. "
        "Prefer specific controls and operational steps over vague policy talk. "
        "If you don't know or lack information, say so plainly."
    )

    user_content = payload.question
    if payload.context:
        user_content += f"\n\nAdditional context: {payload.context}"

    try:
        completion = client.chat.completions.create(
            model="gpt-4.1-mini",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_content},
            ],
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"OpenAI error: {e}")

    answer = completion.choices[0].message.content.strip()
    return AgentResponse(answer=answer, reasoning=None)


# --- NEW: Minimal browser UI for the agent ----------------------------------


@app.get("/ui", response_class=HTMLResponse)
async def ui():
    return """
<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>ExecLayer Governance Agent</title>
    <style>
      body { background:#060606; color:#eee; font-family:system-ui, -apple-system, sans-serif; padding:24px; }
      h1 { font-size:20px; margin-bottom:8px; }
      textarea { width:100%; min-height:100px; background:#111; color:#eee; border:1px solid #333; padding:8px; }
      input { width:100%; background:#111; color:#eee; border:1px solid #333; padding:6px; margin-top:4px; }
      button { margin-top:8px; padding:8px 16px; background:#6366f1; color:white; border:0; cursor:pointer; }
      button:disabled { opacity:0.6; cursor:wait; }
      #answer { margin-top:16px; white-space:pre-wrap; font-size:14px; }
    </style>
  </head>
  <body>
    <h1>ExecLayer Kernel – AI Governance Agent</h1>
    <p>Ask a question about AI governance, controls, or risk management. The agent answers as the ExecLayer kernel.</p>
    <label>Question</label>
    <textarea id="question" placeholder="What controls do I need for audit-grade traceability on o1 in the EU?"></textarea>
    <label>Context (optional)</label>
    <input id="context" placeholder="e.g., We are a US healthcare provider using o1 for triage." />
    <button id="send">Send</button>
    <div id="answer"></div>

    <script>
      const btn = document.getElementById('send');
      const qEl = document.getElementById('question');
      const cEl = document.getElementById('context');
      const out = document.getElementById('answer');

      btn.onclick = async () => {
        const question = qEl.value.trim();
        const context = cEl.value.trim();
        if (!question) {
          alert('Please enter a question.');
          return;
        }
        btn.disabled = true;
        out.textContent = 'Thinking...';

        try {
          const res = await fetch('/agent', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ question, context: context || null })
          });
          const data = await res.json();
          if (!res.ok) {
            out.textContent = 'Error: ' + (data.detail || JSON.stringify(data));
          } else {
            out.textContent = data.answer || JSON.stringify(data);
          }
        } catch (err) {
          out.textContent = 'Network error: ' + err;
        } finally {
          btn.disabled = false;
        }
      };
    </script>
  </body>
</html>
"""
