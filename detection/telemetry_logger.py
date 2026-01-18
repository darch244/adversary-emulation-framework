"""Synthetic Windows Security / Sysmon event emitter.

Produces in-memory events matching Microsoft Event XML / JSON schema shapes
for Sysmon event IDs 1, 3, 7, 8, 10, 11, 13 (plus Windows Security 4698)
that the Sigma engine and detection matrix consume.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from core.models import TelemetryEvent


@dataclass
class SyntheticTelemetryLogger:
    """Collects ``TelemetryEvent`` payloads and exposes schema helpers."""

    computer: str = "AEF-SIMHOST"
    events: list[TelemetryEvent] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.events)

    def emit(self, event: TelemetryEvent) -> TelemetryEvent:
        self.events.append(event)
        return event

    def emit_process_create(
        self,
        *,
        image: str,
        command_line: str,
        user: str,
        pid: int,
        parent_pid: int | None = None,
        hashes: str = "SHA256=DUMMY",
    ) -> TelemetryEvent:
        return self.emit(
            TelemetryEvent(
                event_id=1,
                channel="Microsoft-Windows-Sysmon/Operational",
                provider="Microsoft-Windows-Sysmon",
                computer=self.computer,
                image=image,
                command_line=command_line,
                user=user,
                process_id=pid,
                source_process_id=parent_pid,
                hashes=hashes,
            )
        )

    def emit_network_connection(
        self,
        *,
        image: str,
        destination_ip: str,
        destination_port: int,
        process_id: int = 4,
        user: str = "NT AUTHORITY\\SYSTEM",
    ) -> TelemetryEvent:
        return self.emit(
            TelemetryEvent(
                event_id=3,
                channel="Microsoft-Windows-Sysmon/Operational",
                provider="Microsoft-Windows-Sysmon",
                computer=self.computer,
                image=image,
                destination_ip=destination_ip,
                destination_port=destination_port,
                process_id=process_id,
                user=user,
                event_type="Connect",
            )
        )

    def emit_image_load(
        self,
        *,
        image: str,
        image_loaded: str,
        process_id: int,
        user: str,
    ) -> TelemetryEvent:
        return self.emit(
            TelemetryEvent(
                event_id=7,
                channel="Microsoft-Windows-Sysmon/Operational",
                provider="Microsoft-Windows-Sysmon",
                computer=self.computer,
                image=image,
                target_image=image_loaded,
                process_id=process_id,
                user=user,
            )
        )

    def emit_remote_thread(
        self,
        *,
        source_image: str,
        target_image: str,
        start_address: str = "0x00007FF6AA001000",
    ) -> TelemetryEvent:
        return self.emit(
            TelemetryEvent(
                event_id=8,
                channel="Microsoft-Windows-Sysmon/Operational",
                provider="Microsoft-Windows-Sysmon",
                computer=self.computer,
                source_image=source_image,
                target_image=target_image,
                details={"StartAddress": start_address},
            )
        )

    def emit_process_access(
        self,
        *,
        source_image: str,
        target_image: str,
        granted_access: str,
        source_pid: int = 4424,
        target_pid: int = 668,
        user: str = "NT AUTHORITY\\SYSTEM",
    ) -> TelemetryEvent:
        return self.emit(
            TelemetryEvent(
                event_id=10,
                channel="Microsoft-Windows-Sysmon/Operational",
                provider="Microsoft-Windows-Sysmon",
                computer=self.computer,
                source_image=source_image,
                target_image=target_image,
                granted_access=granted_access,
                source_process_id=source_pid,
                target_process_id=target_pid,
                user=user,
            )
        )

    def emit_registry_value_set(
        self,
        *,
        image: str,
        target_object: str,
        value_data: str,
        process_id: int = 1900,
        user: str = "AEF\\simuser",
    ) -> TelemetryEvent:
        return self.emit(
            TelemetryEvent(
                event_id=13,
                channel="Microsoft-Windows-Sysmon/Operational",
                provider="Microsoft-Windows-Sysmon",
                computer=self.computer,
                image=image,
                new_key_name=target_object,
                target_object=target_object,
                process_id=process_id,
                user=user,
                details={"NewValue": value_data},
            )
        )

    def schema_payloads(self) -> list[dict[str, Any]]:
        """Return all events as flattened eventlog dictionaries."""
        return [e.to_eventlog_dict() for e in self.events]

    def clear(self) -> None:
        self.events.clear()

    def since(self, when: datetime) -> list[TelemetryEvent]:
        """Return events created at or after ``when``."""
        return [e for e in self.events if e.time_created >= when]

    def utc_now(self) -> datetime:
        return datetime.now(UTC)
