"""
Copyright (c) 2026 NNSEC.
SPDX-License-Identifier: AGPL-3.0-or-later
Threat-model note: trust boundary at policy input and OPA decision channel.
"""

from __future__ import annotations

import os
from typing import Any, Dict

import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field


OPA_URL = os.getenv("OPA_URL", "http://opa:8181")

app = FastAPI(title="Sentinel Policy Engine", version="0.1.0")


class PolicyInput(BaseModel):
    tenant_id: str = Field(..., min_length=2)
    user_id: str = Field(..., min_length=2)
    user_role: str = Field(..., min_length=2)
    action: str = Field(..., min_length=2)
    resource: str = Field(..., min_length=2)
    context: Dict[str, Any] = Field(default_factory=dict)


class Decision(BaseModel):
    decision: str
    reason: str
    trace_id: str


@app.get("/healthz")
async def healthz() -> Dict[str, str]:
    return {"status": "ok"}


@app.post("/v1/decision", response_model=Decision)
async def decision(payload: PolicyInput) -> Decision:
    url = f"{OPA_URL}/v1/data/sentinel/authz/decision"
    body = {"input": payload.model_dump()}
    async with httpx.AsyncClient(timeout=2.0) as client:
        resp = await client.post(url, json=body)
    if resp.status_code != 200:
        raise HTTPException(status_code=502, detail="OPA unavailable")
    result = resp.json().get("result")
    if not result:
        raise HTTPException(status_code=500, detail="Malformed OPA response")
    return Decision(
        decision=result.get("decision", "deny"),
        reason=result.get("reason", "default deny"),
        trace_id=result.get("trace_id", "trace-unset"),
    )
