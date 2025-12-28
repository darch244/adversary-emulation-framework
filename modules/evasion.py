"""Safe Defense Evasion simulation modules (T1562.001, T1055).

Emit fraudulent-events telemetry: AMSI/ETW tampering signatures and
process-hollowing metadata, all fully in-memory.
"""

from __future__ import annotations

from datetime import UTC, datetime

from core.models import AttackModuleResult
from modules.base import BaseModule

WIN_SYSMON_OP = "Microsoft-Windows-Sysmon/Operational"
WIN_SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"


class AmsiPatchSimulator(BaseModule):
    """T1562.001 — Impair Defenses (AMSIMsiPatch).

    Emit the AMSI-disable telemetry shape: a Sysmon OpenProcess/ProcessAccess
    event (Event 10) against ``amsi.dll`` followed by an ImageLoad (Event 7)
    for the patched component, describing the AmsiScanBuffer region.
    """

    def validate(self) -> bool:
        subsystem = str(self.parameters.get("subsystem", "AmsiScanBuffer"))
        return subsystem in {"AmsiScanBuffer", "AmsiContext", "AmsiInitialize"}

    def execute(self) -> AttackModuleResult:
        started = datetime.now(UTC)
        subsystem = str(self.parameters.get("subsystem", "AmsiScanBuffer"))
        proc_id = self.agent.pid or 3100
        self.emit_telemetry(
            event_id=10,
            channel=WIN_SYSMON_OP,
            provider=WIN_SYSMON_PROVIDER,
            computer=self.agent.hostname,
            source_image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            source_process_id=proc_id,
            target_image="C:\\Windows\\System32\\amsi.dll",
            target_process_id=proc_id,
            granted_access="0x1FFFFF",
            rule_name="AMSI",
            event_type="ProtectVirtualMemory",
            user=self.agent.user,
            details={"subsystem": subsystem, "region": "amsi!AmsiScanBuffer"},
        )
        self.emit_telemetry(
            event_id=7,
            channel=WIN_SYSMON_OP,
            provider=WIN_SYSMON_PROVIDER,
            computer=self.agent.hostname,
            image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            process_id=proc_id,
            source_process_id=proc_id,
            target_image="C:\\Windows\\System32\\amsi.dll",
            target_process_id=proc_id,
            user=self.agent.user,
            details={"image_loaded": "amsi.dll", "subsystem": subsystem},
        )
        return AttackModuleResult(
            module="amsi_patch_sim",
            technique_id="T1562.001",
            success=True,
            summary=(f"Emitted AMSI bypass telemetry targeting {subsystem}"),
            details={
                "subsystem": subsystem,
                "target": "amsi.dll",
                "events_emitted": 2,
            },
            started_at=started,
            duration_ms=17.0,
        )

    def rollback(self) -> AttackModuleResult | None:
        return None


class ProcessHollowingTelemetry(BaseModule):
    """T1055.012 — Process Hollowing (telemetry sim).

    Emit the CreateRemoteThread (Event 8) + hollowed-process (Event 1 with
    suspended caveat) metadata describing a hollowed ``svchost.exe``
    instance — without creating a real process.
    """

    def validate(self) -> bool:
        template = str(
            self.parameters.get(
                "template_process", "C:\\Windows\\System32\\svchost.exe"
            )
        )
        return template.lower().endswith(".exe")

    def execute(self) -> AttackModuleResult:
        started = datetime.now(UTC)
        template = str(
            self.parameters.get(
                "template_process", "C:\\Windows\\System32\\svchost.exe"
            )
        )
        proc_id = self.agent.pid or 3300
        self.emit_telemetry(
            event_id=8,
            channel=WIN_SYSMON_OP,
            provider=WIN_SYSMON_PROVIDER,
            computer=self.agent.hostname,
            source_image=template,
            source_process_id=proc_id,
            target_image=template,
            target_process_id=proc_id,
            rule_name="Hollowing",
            event_type="CreateRemoteThread",
            user=self.agent.user,
            details={"start_address": "0x00007FF6AA001000", "suspended": True},
        )
        self.emit_telemetry(
            event_id=1,
            channel=WIN_SYSMON_OP,
            provider=WIN_SYSMON_PROVIDER,
            computer=self.agent.hostname,
            image=template,
            command_line="svchost.exe -k AEFSimulation",
            user=self.agent.user,
            process_id=proc_id,
            source_process_id=proc_id,
            hashes="SHA256=DUMMY_HASH",
            integrity_level="High",
            details={"hollowed": True, "template": template},
        )
        return AttackModuleResult(
            module="process_hollowing_telemetry",
            technique_id="T1055",
            success=True,
            summary=f"Emitted process-hollowing telemetry against {template}",
            details={
                "template": template,
                "events_emitted": 2,
                "hollowed": True,
            },
            started_at=started,
            duration_ms=23.0,
        )

    def rollback(self) -> AttackModuleResult | None:
        return None
