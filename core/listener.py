"""Asynchronous FastAPI C2 listener with malleable transforms.

Provides the HTTP endpoint surface that a beacon uses for registration and
heartbeat/tasking.  Supports both a live ASGI server (uvicorn) and an
in-process ``httpx.ASGITransport`` path for hermetic ``--mock`` testing.
"""

from __future__ import annotations

import base64
import random
import time
import uuid
from typing import Any

import yaml
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from core.crypto import CryptoHandler, RSACipher
from core.models import Agent, C2Task, C2TaskStatus, TelemetryEvent
from core.orchestrator import Campaign, Orchestrator


def _uuid8() -> str:
    return uuid.uuid4().hex[:8]


# ---------------------------------------------------------------------------
# Malleable profile loader
# ---------------------------------------------------------------------------


def load_profile(path: str) -> dict[str, Any]:
    """Load a malleable C2 profile YAML file."""
    with open(path, encoding="utf-8") as fh:
        data: dict[str, Any] = yaml.safe_load(fh) or {}
    return data


def apply_malleable_transform(
    payload: dict[str, Any],
    profile: dict[str, Any],
) -> dict[str, Any]:
    """Inject jitter / junk bytes and extra headers dictated by the profile."""
    malleable = profile.get("malleable", {})
    prepend = malleable.get("prepend_junk", 0)
    postpend = malleable.get("postpend_junk", 0)
    if prepend > 0:
        payload["_junk_prefix"] = base64.b64encode(random.randbytes(prepend)).decode()
    if postpend > 0:
        payload["_junk_suffix"] = base64.b64encode(random.randbytes(postpend)).decode()
    return payload


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------


def build_listener(
    rsa_cipher: RSACipher,
    profile_path: str | None = None,
    campaign: Campaign | None = None,
) -> FastAPI:
    """Construct the FastAPI app wired to an ``Orchestrator``."""

    app = FastAPI(title="AEF C2 Listener")
    rsa = rsa_cipher
    crypto_handler = CryptoHandler(rsa)

    profile: dict[str, Any] = {}
    if profile_path is not None:
        profile = load_profile(profile_path)

    camp = campaign or Campaign(
        campaign_name="default", campaign_id="DEF-001", description="default"
    )
    orchestrator = Orchestrator(campaign=camp, rsa_cipher=rsa_cipher)

    # ---- POST /register -------------------------------------------------
    @app.post("/register")
    async def register(request: Request) -> JSONResponse:
        body = await request.json()
        hostname = body.get("hostname", "unknown")
        user = body.get("user", "unknown")
        platform_str = body.get("platform", "windows")
        arch = body.get("arch", "x86_64")
        pid = body.get("pid", 0)
        agent = Agent(
            agent_id=_uuid8(),
            hostname=hostname,
            user=user,
            platform=platform_str,
            arch=arch,
            pid=pid,
        )
        registered = orchestrator.register_agent(agent)
        session = crypto_handler.create_session()
        wrapped_key_bytes = session["wrapped_key"]
        if not isinstance(wrapped_key_bytes, bytes):
            raise RuntimeError("session handshake failed")
        orchestrator.agents[registered.agent_id] = orchestrator.agents[
            registered.agent_id
        ].model_copy(update={"session_key_wrapped": wrapped_key_bytes})
        response: dict[str, Any] = {
            "agent_id": registered.agent_id,
            "session_key_wrapped": base64.b64encode(wrapped_key_bytes).decode(),
        }
        response = apply_malleable_transform(response, profile)
        return JSONResponse(content=response)

    # ---- POST /task (heartbeat / tasking) -------------------------------
    @app.post("/task")
    async def tasking(request: Request) -> JSONResponse:
        body = await request.json()
        agent_id = body.get("agent_id", "")
        agent = orchestrator.agents.get(agent_id)
        if agent is None:
            return JSONResponse(
                status_code=404,
                content={"error": f"unknown agent {agent_id}"},
            )
        now = time.time()
        base_sleep = profile.get("sleep", {}).get("base_seconds", 60)
        jitter = profile.get("sleep", {}).get("jitter_percent", 35)
        jitter_ms = (jitter / 100) * base_sleep
        sleep_actual = base_sleep + random.uniform(-jitter_ms, jitter_ms)
        pending = orchestrator.pending_tasks(agent_id)
        task_dicts = [
            {
                "task_id": t.task_id,
                "module": t.module,
                "technique_id": t.technique_id,
                "parameters": t.parameters,
            }
            for t in pending
        ]
        response_payload: dict[str, Any] = {
            "agent_id": agent_id,
            "tasks": task_dicts,
            "sleep_seconds": round(max(sleep_actual, 1), 2),
            "ts": now,
        }
        response_payload = apply_malleable_transform(response_payload, profile)
        return JSONResponse(content=response_payload)

    # ---- POST /result (telemetry submission) ----------------------------
    @app.post("/result")
    async def submit_result(request: Request) -> JSONResponse:

        from core.models import AttackModuleResult

        body = await request.json()
        task_id = body.get("task_id", "")
        success = body.get("success", False)
        summary = body.get("summary", "")
        event_data = body.get("telemetry", {})
        agent_id = body.get("agent_id", "")
        module_name = body.get("module", "")
        tech = body.get("technique_id", "T0000")
        result = AttackModuleResult(
            module=module_name,
            technique_id=tech,
            success=success,
            summary=summary,
            details=event_data,
        )
        if task_id not in orchestrator.tasks:
            # Upsert: results may arrive for client-staged tasks the queue
            # has not registered (hermetic/provider-driven runs).
            placeholder = C2Task(
                task_id=task_id if task_id else _uuid8(),
                agent_id=agent_id,
                module=module_name,
                technique_id=tech,
                status=C2TaskStatus.COMPLETED,
            )
            orchestrator.tasks[placeholder.task_id] = placeholder
            orchestrator.complete_task(placeholder.task_id, result)
        else:
            orchestrator.complete_task(task_id, result)
        if event_data:
            event = TelemetryEvent(
                event_id=event_data.get("event_id", 1),
                channel=event_data.get(
                    "channel", "Microsoft-Windows-Sysmon/Operational"
                ),
                provider=event_data.get("provider", "Microsoft-Windows-Sysmon"),
                computer=event_data.get("computer", "unknown"),
                image=event_data.get("image"),
                command_line=event_data.get("command_line"),
                user=event_data.get("user"),
                process_id=event_data.get("process_id"),
                target_object=event_data.get("target_object"),
            )
            orchestrator.record_telemetry(event)
        return JSONResponse(content={"status": "accepted"})

    # ---- GET /summary ---------------------------------------------------
    @app.get("/summary")
    async def summary() -> JSONResponse:
        return JSONResponse(content=orchestrator.summary())

    return app
