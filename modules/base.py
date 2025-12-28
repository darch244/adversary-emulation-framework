"""BaseModule — abstract interface for every adversary emulation unit.

All modules inherit from ``BaseModule`` and implement ``validate``,
``execute``, and ``rollback``.  Telemetry emission is provided as a
concrete helper — modules call ``emit_telemetry`` to build the event list
that the detection/validation layer consumes.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from core.models import AttackModuleResult, TelemetryEvent

if TYPE_CHECKING:
    from core.models import Agent
    from core.orchestrator import Orchestrator


class BaseModule(ABC):
    """Abstract emulation unit.

    Subclasses MUST implement all three abstract methods.  The ``telemetry``
    list is populated by calling ``emit_telemetry`` during ``execute`` and is
    consumed after execution by the orchestrator or detection layer.
    """

    def __init__(
        self,
        agent: Agent,
        parameters: dict[str, Any] | None = None,
        orchestrator: Orchestrator | None = None,
    ) -> None:
        self.agent = agent
        self.parameters = parameters or {}
        self.orchestrator = orchestrator
        self.telemetry_events: list[TelemetryEvent] = []
        self._rolled_back = False

    @abstractmethod
    def validate(self) -> bool:
        """Return ``True`` iff the module can run with the current parameters."""
        ...

    @abstractmethod
    def execute(self) -> AttackModuleResult:
        """Perform the in-memory emulation and return structured results."""
        ...

    @abstractmethod
    def rollback(self) -> AttackModuleResult | None:
        """Undo any local-side-effect created by ``execute``.

        Return a result describing the rollback, or ``None`` if the module
        has no side-effects to undo.
        """
        ...

    # -- telemetry helper ------------------------------------------------

    def emit_telemetry(
        self,
        *,
        event_id: int,
        channel: str,
        provider: str,
        computer: str,
        image: str | None = None,
        command_line: str | None = None,
        user: str | None = None,
        process_id: int | None = None,
        target_object: str | None = None,
        new_key_name: str | None = None,
        target_image: str | None = None,
        target_process_id: int | None = None,
        source_process_id: int | None = None,
        source_image: str | None = None,
        granted_access: str | None = None,
        event_type: str | None = None,
        task_name: str | None = None,
        destination_ip: str | None = None,
        destination_port: int | None = None,
        rule_name: str | None = None,
        details: dict[str, Any] | None = None,
        time_created: datetime | None = None,
        hashes: str | None = None,
        integrity_level: str | None = None,
    ) -> TelemetryEvent:
        """Construct a ``TelemetryEvent`` and append it to ``self.telemetry_events``.

        All keyword arguments map directly to the ``TelemetryEvent`` schema.
        Returns the constructed event for convenience.
        """
        event = TelemetryEvent(
            event_id=event_id,
            channel=channel,
            provider=provider,
            computer=computer,
            image=image,
            command_line=command_line,
            user=user,
            process_id=process_id,
            target_object=target_object,
            new_key_name=new_key_name,
            target_image=target_image,
            target_process_id=target_process_id,
            source_process_id=source_process_id,
            source_image=source_image,
            granted_access=granted_access,
            event_type=event_type,
            task_name=task_name,
            destination_ip=destination_ip,
            destination_port=destination_port,
            rule_name=rule_name,
            details=details or {},
            time_created=time_created or datetime.now(UTC),
            hashes=hashes,
            integrity_level=integrity_level,
        )
        self.telemetry_events.append(event)
        return event
