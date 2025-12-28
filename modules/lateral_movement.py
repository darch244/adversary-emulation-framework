"""Lateral movement emulation modules (T1047, T1021.002).

Dispatcher abstractions that *describe* WMI / SMB command execution flows
and emit the telemetry an analyst would expect (wmiprvse execution event,
SMB ADMIN$ connection event) without performing real movement.
"""

from __future__ import annotations

from datetime import UTC, datetime

from core.models import AttackModuleResult
from modules.base import BaseModule

WIN_SYSMON_OP = "Microsoft-Windows-Sysmon/Operational"
WIN_SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"


class WMIPrivseDispatch(BaseModule):
    """T1047 — Windows Management Instrumentation.

    Emit a Sysmon Event 1 for a ``wmiprvse.exe`` process creation carrying the
    dispatched remote command line, matching the classic suspicious-WMI
    detection shape.
    """

    def validate(self) -> bool:
        command = str(self.parameters.get("command", "whoami /all"))
        return bool(command.strip())

    def execute(self) -> AttackModuleResult:
        started = datetime.now(UTC)
        command = str(self.parameters.get("command", "whoami /all"))
        proc_id = self.agent.pid + 100 if self.agent.pid else 2020
        self.emit_telemetry(
            event_id=1,
            channel=WIN_SYSMON_OP,
            provider=WIN_SYSMON_PROVIDER,
            computer=self.agent.hostname,
            image="C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
            command_line=command,
            user=self.agent.user,
            process_id=proc_id,
            source_process_id=self.agent.pid or 1204,
            details={"provider": "WMI", "namespace": "root\\cimv2"},
        )
        return AttackModuleResult(
            module="wmiprvse_dispatch",
            technique_id="T1047",
            success=True,
            summary=f"Dispatched WMI command through WmiPrvSE.exe: '{command}'",
            details={"command": command, "dispatcher": "WmiPrvSE.exe"},
            started_at=started,
            duration_ms=21.0,
        )

    def rollback(self) -> AttackModuleResult | None:
        return None


class SMBAdminShareSimulator(BaseModule):
    """T1021.002 — SMB/Windows Admin Shares.

    Emit a Sysmon Event 3 (network connect) toward an ADMIN$ share on a
    target host, describing the SMB session establishment attempt.
    """

    def validate(self) -> bool:
        host = str(self.parameters.get("target_host", "DC01.corp.local"))
        return bool(host.strip())

    def execute(self) -> AttackModuleResult:
        started = datetime.now(UTC)
        host = str(self.parameters.get("target_host", "DC01.corp.local"))
        share = str(self.parameters.get("share", "ADMIN$"))
        port = 445
        self.emit_telemetry(
            event_id=3,
            channel=WIN_SYSMON_OP,
            provider=WIN_SYSMON_PROVIDER,
            computer=self.agent.hostname,
            image="C:\\Windows\\System32\\svchost.exe",
            command_line="-k NetworkService",
            user=self.agent.user,
            process_id=self.agent.pid or 1700,
            destination_ip=host,
            destination_port=port,
            details={
                "share": share,
                "protocol": "SMB2",
                "tree_connect": f"\\\\{host}\\{share}",
            },
        )
        return AttackModuleResult(
            module="smb_admin_share",
            technique_id="T1021.002",
            success=True,
            summary=f"Simulated SMB ADMIN$ connect to {host}",
            details={"target": host, "share": share},
            started_at=started,
            duration_ms=18.0,
        )

    def rollback(self) -> AttackModuleResult | None:
        return None
