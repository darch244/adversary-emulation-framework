"""Campaign state manager and task routing for the C2 platform."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from core.crypto import AESCipher, CryptoHandler, RSACipher
from core.models import (
    Agent,
    AgentStatus,
    AttackModuleResult,
    C2Task,
    C2TaskStatus,
    TelemetryEvent,
)
from detection.telemetry_logger import SyntheticTelemetryLogger


def _uuid8() -> str:
    return uuid.uuid4().hex[:8]


class ModuleRegistryError(Exception):
    """Raised when an attack-chain yaml references an unknown module."""


@dataclass
class Campaign:
    """In-memory campaign metadata parsed from ``attack_chains.yaml``."""

    campaign_name: str
    campaign_id: str
    description: str
    stages: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def from_yaml(cls, path: Path | str) -> Campaign:
        data = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
        return cls(
            campaign_name=data["campaign_name"],
            campaign_id=data["campaign_id"],
            description=data["description"],
            stages=data.get("stages", []),
        )

    def iter_modules(self) -> list[tuple[str, dict[str, Any]]]:
        """Yield ``(module_name, config)`` for every stage in order."""
        modules: list[tuple[str, dict[str, Any]]] = []
        for stage in self.stages:
            for spec in stage.get("modules", []):
                modules.append(
                    (spec["module"], {"parameters": spec.get("parameters", {})})
                )
        return modules


class Orchestrator:
    """Owns agents, tasks, and the campaign; routes work to beacons.

    The orchestrator is the single source of truth for campaign state. In
    hermetic/``--mock`` mode the CLI drives it directly through an in-process
    executor; in live mode the listener forwards beacon traffic to it.
    """

    def __init__(
        self,
        campaign: Campaign,
        rsa_cipher: RSACipher,
        telemetry: SyntheticTelemetryLogger | None = None,
    ) -> None:
        self.campaign = campaign
        self.rsa = rsa_cipher
        self.crypto = CryptoHandler(rsa_cipher)
        self.agents: dict[str, Agent] = {}
        self.tasks: dict[str, C2Task] = {}
        self.results: dict[str, AttackModuleResult] = {}
        self.telemetry = telemetry or SyntheticTelemetryLogger(
            computer=campaign.campaign_name
        )
        self._task_order: list[str] = []

    def register_agent(self, agent: Agent) -> Agent:
        """Register (or reactivate) an agent and issue its session key."""
        wrapped = (
            agent.session_key_wrapped or self.crypto.create_session()["wrapped_key"]
        )
        candidate = agent.model_copy(
            update={
                "session_key_wrapped": wrapped,
                "status": AgentStatus.ACTIVE,
                "last_seen": datetime.now(UTC),
            }
        )
        self.agents[agent.agent_id] = candidate
        return candidate

    def session_cipher_for(self, agent_id: str) -> AESCipher | None:
        agent = self.agents.get(agent_id)
        if agent is None or agent.session_key_wrapped is None:
            return None
        return self.crypto.unwrap_session(agent.session_key_wrapped)

    def enqueue_task(self, task: C2Task) -> C2Task:
        """Queue a task for a registered agent."""
        if task.agent_id not in self.agents:
            raise KeyError(f"unknown agent {task.agent_id}")
        self.tasks[task.task_id] = task
        self._task_order.append(task.task_id)
        self.agents[task.agent_id].task_queue_size += 1
        return task

    def _default_task(
        self, agent_id: str, module: str, parameters: dict[str, Any]
    ) -> C2Task:
        return C2Task(
            task_id=_uuid8(),
            agent_id=agent_id,
            module=module,
            technique_id="T0000",
            parameters=parameters,
        )

    def stage_campaign(
        self, agent_id: str, configs: list[tuple[str, dict[str, Any]]] | None = None
    ) -> list[C2Task]:
        """Convert campaign stages into queued tasks for one agent."""
        if agent_id not in self.agents:
            raise KeyError(f"unknown agent {agent_id}")
        specs = configs if configs is not None else self.campaign.iter_modules()
        tasks: list[C2Task] = []
        technique_by_module: dict[str, str] = {}
        for stage in self.campaign.stages:
            for spec in stage.get("modules", []):
                technique_by_module[spec["module"]] = spec.get("technique_id", "T0000")
        for module, cfg in specs:
            task = self._default_task(agent_id, module, cfg["parameters"])
            task = task.model_copy(
                update={"technique_id": technique_by_module.get(module, "T0000")}
            )
            self.enqueue_task(task)
            tasks.append(task)
        return tasks

    def pending_tasks(self, agent_id: str) -> list[C2Task]:
        """Return queued tasks in FIFO order, demoting status to DELIVERED."""
        delivered: list[C2Task] = []
        for task_id in self._task_order:
            task = self.tasks[task_id]
            if task.agent_id != agent_id:
                continue
            if task.status is C2TaskStatus.PENDING:
                updated = task.model_copy(update={"status": C2TaskStatus.DELIVERED})
                self.tasks[task_id] = updated
                delivered.append(updated)
        return delivered

    def complete_task(self, task_id: str, result: AttackModuleResult) -> None:
        """Record a module result and mark its task completed."""
        task = self.tasks.get(task_id)
        if task is None:
            raise KeyError(f"unknown task {task_id}")
        if task.agent_id not in self.agents:
            raise KeyError(f"unknown agent {task.agent_id}")
        now = datetime.now(UTC)
        updated = task.model_copy(
            update={
                "status": C2TaskStatus.COMPLETED,
                "executed_at": result.started_at,
                "completed_at": now,
            }
        )
        self.tasks[task_id] = updated
        self.results[task_id] = result
        queue = self.agents[task.agent_id].task_queue_size
        if queue > 0:
            self.agents[task.agent_id].task_queue_size = queue - 1
        current = self.agents[task.agent_id]
        self.agents[task.agent_id] = current.model_copy(
            update={"last_seen": now, "status": AgentStatus.ACTIVE}
        )

    def record_telemetry(self, event: TelemetryEvent) -> None:
        """Persist a telemetry event through the synthetic logger."""
        if self.telemetry is not None:
            self.telemetry.emit(event)

    def summary(self) -> dict[str, Any]:
        """Produce a plain-data snapshot for reports and diagnostics."""
        return {
            "campaign": self.campaign.campaign_name,
            "campaign_id": self.campaign.campaign_id,
            "agents": [
                a.model_dump(mode="json", exclude={"session_key_wrapped"})
                for a in self.agents.values()
            ],
            "tasks_total": len(self.tasks),
            "tasks_completed": sum(
                1 for t in self.tasks.values() if t.status is C2TaskStatus.COMPLETED
            ),
            "tasks_failed": sum(
                1 for t in self.tasks.values() if t.status is C2TaskStatus.FAILED
            ),
            "events_emitted": self.telemetry.count if self.telemetry else 0,
        }

    def exec_module(
        self, module_name: str, agent: Agent, parameters: dict[str, Any]
    ) -> AttackModuleResult:
        """Execute a named module for a task in-process (hermetic emulation).

        Resolves the module class from the ``modules`` package using a fixed,
        explicit registry rather than dynamic ``__import__`` by user string.
        """
        module_cls = self.module_classes().get(module_name)
        if module_cls is None:
            raise ModuleRegistryError(f"unknown module '{module_name}'")
        module = module_cls(agent=agent, parameters=parameters, orchestrator=self)
        result = module.execute()
        for event in module.telemetry_events:
            event.technique_id = result.technique_id
            self.record_telemetry(event)
        return result

    @staticmethod
    def module_classes() -> dict[str, type[Any]]:
        """Statically-known registry mapping module names to classes."""
        from modules.credential_access import (
            DPAPIQuerySimulator,
            LsassDumpAccessSimulator,
        )
        from modules.discovery import (
            NetworkConnectionsModule,
            SystemProfileModule,
            UserEnumModule,
        )
        from modules.evasion import (
            AmsiPatchSimulator,
            ProcessHollowingTelemetry,
        )
        from modules.lateral_movement import SMBAdminShareSimulator, WMIPrivseDispatch
        from modules.persistence import RegistryRunKeyModule, ScheduledTaskModule

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
