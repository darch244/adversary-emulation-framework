"""Simulated implant lifecycle and heartbeat loop.

``Beacon`` drives the classic C2 loop: register -> task fetch -> execute
(via ``ModuleExecutor``) -> result/telemetry submission.  It is fully
testable without any network because the transport is pluggable (an
``httpx.AsyncClient`` in live mode, an ``ASGITransport`` in hermetic mode).
"""

from __future__ import annotations

import asyncio
import platform
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

import httpx

from core.models import Agent, TelemetryEvent
from modules.base import BaseModule
from modules.credential_access import DPAPIQuerySimulator, LsassDumpAccessSimulator
from modules.discovery import (
    NetworkConnectionsModule,
    SystemProfileModule,
    UserEnumModule,
)
from modules.evasion import AmsiPatchSimulator, ProcessHollowingTelemetry
from modules.lateral_movement import SMBAdminShareSimulator, WMIPrivseDispatch
from modules.persistence import RegistryRunKeyModule, ScheduledTaskModule


class Transport(Protocol):
    """Minimal transport abstraction implemented by httpx clients."""

    async def post(self, url: str, *, json: dict[str, Any]) -> httpx.Response: ...


@dataclass
class BeaconConfig:
    """Runtime configuration for an implant simulation."""

    listener_url: str = "http://testserver"
    hostname: str | None = None
    user: str | None = None
    agent_id: str | None = None
    jitter: float = 0.0
    max_beats: int = 0  # 0 == run until no tasks remain


class Beacon:
    """State machine for the simulated implant lifecycle."""

    def __init__(
        self,
        transport: Transport,
        config: BeaconConfig | None = None,
    ) -> None:
        self.transport = transport
        self.config = config or BeaconConfig()
        self.agent_id: str | None = self.config.agent_id
        self.tasks_completed = 0
        self.results: list[dict[str, Any]] = []
        self._start = time.monotonic()

    # -- lifecycle ---------------------------------------------------------

    def _identity(self) -> Agent:
        hostname = self.config.hostname or platform.node() or "SIM-HOST"
        user = self.config.user or "AEF\\simuser"
        return Agent(
            agent_id=self.agent_id or uuid.uuid4().hex[:16],
            hostname=hostname,
            user=user,
            platform="windows",
            arch="x86_64",
            pid=14141,
        )

    async def register(self) -> None:
        """Perform the registration handshake."""
        identity = self._identity()
        resp = await self.transport.post(
            f"{self.config.listener_url}/register",
            json={
                "hostname": identity.hostname,
                "user": identity.user,
                "platform": identity.platform,
                "arch": identity.arch,
                "pid": identity.pid,
            },
        )
        resp.raise_for_status()
        data = resp.json()
        self.agent_id = data["agent_id"]
        self._wrapped_key = bytes(data.get("session_key_wrapped", "").encode())

    async def heartbeat(self) -> list[dict[str, Any]]:
        """Fetch pending tasks; returns delivered task descriptors."""
        assert self.agent_id is not None
        resp = await self.transport.post(
            f"{self.config.listener_url}/task",
            json={"agent_id": self.agent_id, "ts": time.time()},
        )
        resp.raise_for_status()
        return resp.json().get("tasks", [])

    async def submit(
        self,
        *,
        task_id: str,
        module: str,
        technique_id: str,
        success: bool,
        summary: str,
        telemetry: dict[str, Any],
    ) -> None:
        """Report the outcome of one task plus its emitted telemetry."""
        assert self.agent_id is not None
        resp = await self.transport.post(
            f"{self.config.listener_url}/result",
            json={
                "agent_id": self.agent_id,
                "task_id": task_id,
                "module": module,
                "technique_id": technique_id,
                "success": success,
                "summary": summary,
                "telemetry": telemetry,
            },
        )
        resp.raise_for_status()
        self.tasks_completed += 1
        self.results.append(
            {"task_id": task_id, "success": success, "summary": summary}
        )

    # -- synchronous module resolution ------------------------------------

    @staticmethod
    def module_classes() -> dict[str, type[BaseModule]]:
        return {
            "system_profile": SystemProfileModule,
            "user_enum": UserEnumModule,
            "network_connections": NetworkConnectionsModule,
            "lsass_dump_access": LsassDumpAccessSimulator,
            "dpapi_query": DPAPIQuerySimulator,
            "wmiprvse_dispatch": WMIPrivseDispatch,
            "smb_admin_share": SMBAdminShareSimulator,
            "registry_runkey": RegistryRunKeyModule,
            "scheduled_task": ScheduledTaskModule,
            "amsi_patch_sim": AmsiPatchSimulator,
            "process_hollowing_telemetry": ProcessHollowingTelemetry,
        }

    def execute_task(self, task: dict[str, Any]) -> tuple[bool, str, dict[str, Any]]:
        """Run one task synchronously inside a sandbox executor."""
        from agent.executor import ModuleExecutor

        module_name = str(task["module"])
        technique_id = str(task.get("technique_id", "T0000"))
        parameters = dict(task.get("parameters") or {})
        agent = Agent(
            agent_id=self.agent_id or "unknown",
            hostname=self.config.hostname or "SIM-HOST",
            user=self.config.user or "AEF\\simuser",
            pid=14141,
        )
        executor = ModuleExecutor(
            module_name=module_name,
            agent=agent,
            parameters=parameters,
            technique_id=technique_id,
        )
        result = executor.run()
        telemetry_payload = _telemetry_to_submit(executor.events)
        return result.success, result.summary, telemetry_payload

    # -- main loop ---------------------------------------------------------

    async def run(
        self,
        task_provider: Callable[[], list[dict[str, Any]]] | None = None,
    ) -> None:
        """Beat-until-drained main loop.

        ``task_provider`` lets tests/CLI inject tasks directly; the default
        fetches from the listener heartbeat endpoint.
        """
        await self.register()
        beats = 0
        while True:
            tasks = task_provider() if task_provider else await self.heartbeat()
            if not tasks:
                break
            for task in tasks:
                ok, summary, telemetry = self.execute_task(task)
                await self.submit(
                    task_id=task["task_id"],
                    module=task["module"],
                    technique_id=task.get("technique_id", "T0000"),
                    success=ok,
                    summary=summary,
                    telemetry=telemetry,
                )
            beats += 1
            if self.config.max_beats and beats >= self.config.max_beats:
                break
            if self.config.jitter:
                await asyncio.sleep(self.config.jitter)


def _telemetry_to_submit(events: list[TelemetryEvent]) -> dict[str, Any]:
    """Reduce emitted events into the first event's submission shape."""
    if not events:
        return {}
    first = events[0]
    return {
        "event_id": first.event_id,
        "channel": first.channel,
        "provider": first.provider,
        "image": first.image,
        "command_line": first.command_line,
        "user": first.user,
        "process_id": first.process_id,
        "target_object": first.target_object or first.new_key_name,
        "computer": first.computer,
    }
