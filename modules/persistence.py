"""Persistence emulation modules (T1547.001, T1053.005).

Registry RunKey and Scheduled Task wrappers carry **automatic rollback**:
execution records a reversible artifact descriptor and ``rollback()`` returns
the matching cleanup result.  The emitted telemetry feeds the
``registry_run_persistence.yaml`` Sigma rule.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from core.models import AttackModuleResult
from modules.base import BaseModule

WIN_SYSMON_OP = "Microsoft-Windows-Sysmon/Operational"
WIN_SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"

RUN_KEY = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\AEFSimulation"


class RegistryRunKeyModule(BaseModule):
    """T1547.001 — Boot or Logon Autostart Execution (Registry Run).

    Records a fake Run-key value in-memory and emits Sysmon Event 13
    (RegistryValueSet).  ``rollback()`` removes the simulated value.
    """

    def validate(self) -> bool:
        key_name = str(
            self.parameters.get(
                "key_name",
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            )
        )
        return "Run" in key_name and "\\CurrentVersion\\" in key_name

    def execute(self) -> AttackModuleResult:
        started = datetime.now(UTC)
        key_name = str(
            self.parameters.get(
                "key_name",
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
            )
        )
        value_name = "AEFSimulationUpdate"
        value_data = (
            "C:\\Users\\Public\\UpdateHelper\\update.exe --silent --maintenance-window"
        )
        self._rollback_artifact = {"key_name": key_name, "value_name": value_name}
        target_object = f"{key_name}\\{value_name}"
        self.emit_telemetry(
            event_id=13,
            channel=WIN_SYSMON_OP,
            provider=WIN_SYSMON_PROVIDER,
            computer=self.agent.hostname,
            image="C:\\Windows\\System32\\reg.exe",
            new_key_name=target_object,
            target_object=target_object,
            user=self.agent.user,
            process_id=self.agent.pid or 1900,
            details={"value_data": value_data, "event_type": "SetValue"},
        )
        return AttackModuleResult(
            module="registry_runkey",
            technique_id="T1547.001",
            success=True,
            summary=(f"Simulated registry Run key persistence under {key_name}"),
            details={
                "key_name": key_name,
                "value_name": value_name,
                "value_data": value_data,
            },
            started_at=started,
            duration_ms=11.0,
        )

    def rollback(self) -> AttackModuleResult | None:
        if self._rolled_back:
            return None
        self._rolled_back = True
        artifact: dict[str, Any] = getattr(self, "_rollback_artifact", {})
        return AttackModuleResult(
            module="registry_runkey",
            technique_id="T1547.001",
            success=True,
            summary="Removed simulated attached_runkey artifact",
            details={**artifact, "removed": True},
            rolled_back=True,
        )


class ScheduledTaskModule(BaseModule):
    """T1053.005 — Scheduled Task.

    Records an in-memory scheduled-task artifact and emits a Sysmon process
    creation for ``schtasks.exe`` plus a Security-channel 4698 event.
    ``rollback()`` deletes the simulated task.
    """

    def validate(self) -> bool:
        task_name = str(self.parameters.get("task_name", "MicrosoftUpdateTask"))
        return bool(task_name.strip())

    def execute(self) -> AttackModuleResult:
        started = datetime.now(UTC)
        task_name = str(self.parameters.get("task_name", "MicrosoftUpdateTask"))
        schedule = str(self.parameters.get("schedule", "hourly"))
        run_as = f"{self.agent.user} AUTHENTICATED USERS"
        action = (
            "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -enc SQBFAFgA"
        )
        self._rollback_artifact = {"task_name": task_name}
        self.emit_telemetry(
            event_id=1,
            channel=WIN_SYSMON_OP,
            provider=WIN_SYSMON_PROVIDER,
            computer=self.agent.hostname,
            image="C:\\Windows\\System32\\schtasks.exe",
            command_line=(
                f"/create /tn {task_name} /tr {action} /sc {schedule} /ru {run_as}"
            ),
            user=self.agent.user,
            process_id=self.agent.pid or 2100,
            details={"task_name": task_name, "action": action},
        )
        self.emit_telemetry(
            event_id=4698,
            channel="Security",
            provider="Microsoft-Windows-Security-Auditing",
            computer=self.agent.hostname,
            user=self.agent.user,
            task_name=task_name,
            source_process_id=self.agent.pid or 2100,
            process_id=0,
            details={
                "action": action,
                "schedule": schedule,
                "run_as": run_as,
            },
        )
        return AttackModuleResult(
            module="scheduled_task",
            technique_id="T1053.005",
            success=True,
            summary=f"Simulated scheduled task '{task_name}' with {schedule} cadence",
            details={
                "task_name": task_name,
                "schedule": schedule,
                "action": action,
            },
            started_at=started,
            duration_ms=26.0,
        )

    def rollback(self) -> AttackModuleResult | None:
        if self._rolled_back:
            return None
        self._rolled_back = True
        artifact: dict[str, Any] = getattr(self, "_rollback_artifact", {})
        return AttackModuleResult(
            module="scheduled_task",
            technique_id="T1053.005",
            success=True,
            summary="Removed simulated scheduled-task artifact",
            details={**artifact, "removed": True},
            rolled_back=True,
        )
