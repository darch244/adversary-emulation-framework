"""Safe module execution sandbox for the simulated implant.

Resolves a static module-name registry, instantiates the module, validates
parameters, executes, and collects emitted telemetry — without ever invoking
kernel-level or network-facing primitives.
"""

from __future__ import annotations

from typing import Any, ClassVar

from core.models import Agent, AttackModuleResult, TelemetryEvent
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


class UnknownModuleError(Exception):
    """Raised when an executor is asked to run a non-registered module."""


class ModuleExecutor:
    """Fully synchronous, hermetic module runner."""

    _REGISTRY: ClassVar[dict[str, type[BaseModule]]] = {
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

    def __init__(
        self,
        *,
        module_name: str,
        agent: Agent,
        parameters: dict[str, Any] | None = None,
        technique_id: str = "T0000",
    ) -> None:
        self.module_name = module_name
        self.agent = agent
        self.parameters = parameters or {}
        self.technique_id = technique_id
        self.events: list[TelemetryEvent] = []

    def _build(self) -> BaseModule:
        cls = self._REGISTRY.get(self.module_name)
        if cls is None:
            raise UnknownModuleError(f"unknown module '{self.module_name}'")
        return cls(agent=self.agent, parameters=self.parameters)

    def run(self) -> AttackModuleResult:
        """Validate, execute, emit telemetry, and return the structured result."""
        module = self._build()
        if not module.validate():
            from core.models import AttackModuleResult

            return AttackModuleResult(
                module=self.module_name,
                technique_id=self.technique_id,
                success=False,
                summary=f"validation failed for module '{self.module_name}'",
            )
        result = module.execute()
        self.events.extend(module.telemetry_events)
        return result

    def rollback(self) -> AttackModuleResult | None:
        module = self._build()
        return module.rollback()
