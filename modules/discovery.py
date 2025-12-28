"""ATT&CK Discovery modules (T1082, T1087, T1049).

These emit synthetic Windows telemetry without invoking noisy third-party
binaries — enumeration data is produced in-memory and shaped like what real
system discovery would look like.
"""

from __future__ import annotations

import platform
from datetime import UTC, datetime
from typing import Any

from core.models import AttackModuleResult
from modules.base import BaseModule

WIN_SYSMON_OP = "Microsoft-Windows-Sysmon/Operational"
WIN_SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"


class SystemProfileModule(BaseModule):
    """T1082 — System Information Discovery.

    Produce a system-instruction snapshot (OS version, architecture, CPU,
    memory) and emit a Sysmon process-creation event shaped like
    ``cmd /c systeminfo``.
    """

    def validate(self) -> bool:
        return True

    def execute(self) -> AttackModuleResult:
        started = datetime.now(UTC)
        hostname = platform.node() or self.agent.hostname
        profile = {
            "hostname": hostname,
            "os": platform.system(),
            "release": platform.release(),
            "version": platform.version(),
            "architecture": platform.machine(),
            "processor": platform.processor(),
            "python_impl": platform.python_implementation(),
        }
        self.emit_telemetry(
            event_id=1,
            channel=WIN_SYSMON_OP,
            provider=WIN_SYSMON_PROVIDER,
            computer=hostname,
            image="C:\\Windows\\System32\\windows.systeminfo.exe",
            command_line="windows.systeminfo.exe /all",
            user=self.agent.user,
            process_id=self.agent.pid,
            details={"profile": profile},
        )
        return AttackModuleResult(
            module="system_profile",
            technique_id="T1082",
            success=True,
            summary=f"Collected system profile for {hostname}",
            details=profile,
            started_at=started,
            duration_ms=12.0,
        )

    def rollback(self) -> AttackModuleResult | None:
        return None


class UserEnumModule(BaseModule):
    """T1087 — Account Discovery.

    Enumerate local/domain account names in-memory and emit a process-creation
    event for ``net user``.
    """

    def validate(self) -> bool:
        return True

    def execute(self) -> AttackModuleResult:
        started = datetime.now(UTC)
        include_domain = bool(self.parameters.get("include_domain", True))
        local_users = ["Administrator", "DefaultAccount", "Guest"]
        domain_users = ["svc_pentest", "jdoe", "ksmith"] if include_domain else []
        users = sorted(set(local_users + domain_users))
        command = "net user /domain" if include_domain else "net user"
        self.emit_telemetry(
            event_id=1,
            channel=WIN_SYSMON_OP,
            provider=WIN_SYSMON_PROVIDER,
            computer=self.agent.hostname,
            image="C:\\Windows\\System32\\net.exe",
            command_line=command,
            user=self.agent.user,
            process_id=self.agent.pid,
            details={"accounts": users},
        )
        return AttackModuleResult(
            module="user_enum",
            technique_id="T1087",
            success=True,
            summary="Enumerated accounts",
            details={"local_users": local_users, "domain_users": domain_users},
            started_at=started,
            duration_ms=8.0,
        )

    def rollback(self) -> AttackModuleResult | None:
        return None


class NetworkConnectionsModule(BaseModule):
    """T1049 — System Network Connections Discovery.

    Emit a synthetic Sysmon Event 3 (network connect) representative of an
    implant probing internal network state.
    """

    def validate(self) -> bool:
        return True

    def execute(self) -> AttackModuleResult:
        started = datetime.now(UTC)
        conns = [
            ("10.0.20.15", 445),
            ("10.0.20.21", 3389),
            ("10.0.30.7", 5985),
        ]
        details: dict[str, Any] = {"connections": conns}
        for ip, port in conns[:1]:
            self.emit_telemetry(
                event_id=3,
                channel=WIN_SYSMON_OP,
                provider=WIN_SYSMON_PROVIDER,
                computer=self.agent.hostname,
                image="C:\\Windows\\System32\\netstat.exe",
                command_line="netstat -ano",
                user=self.agent.user,
                process_id=self.agent.pid,
                destination_ip=ip,
                destination_port=port,
                details=details,
            )
        return AttackModuleResult(
            module="network_connections",
            technique_id="T1049",
            success=True,
            summary="Enumerated active network connections",
            details=details,
            started_at=started,
            duration_ms=6.0,
        )

    def rollback(self) -> AttackModuleResult | None:
        return None
