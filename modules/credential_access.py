"""Safe Credential Access simulation modules (T1003.001).

These modules emulate the *telemetry* of OS credential access (LSASS process
memory open and DPAPI query) while never touching real process memory.  The
granted-access masks reflect genuine Windows access-mask values:

* ``0x1010`` — PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ
* ``0x1438`` — PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE
               | PROCESS_VM_OPERATION | SYNCHRONIZE

A synthetic Sysmon Event 10 (ProcessAccess) is emitted for each simulated
access against ``lsass.exe``.
"""

from __future__ import annotations

from datetime import UTC, datetime

from core.models import AttackModuleResult
from modules.base import BaseModule

WIN_SYSMON_OP = "Microsoft-Windows-Sysmon/Operational"
WIN_SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"


class LsassDumpAccessSimulator(BaseModule):
    """T1003.001 — LSASS Memory.

    Emits a ProcessAccess (Event 10) telemetry record targeting ``lsass.exe``
    with the configured granted-access mask (default ``0x1010``).
    """

    ACCESS_MASKS = ("0x1010", "0x1438")

    def validate(self) -> bool:
        mask = str(self.parameters.get("access_mask", "0x1010"))
        return mask in self.ACCESS_MASKS

    def execute(self) -> AttackModuleResult:
        started = datetime.now(UTC)
        mask = str(self.parameters.get("access_mask", "0x1010"))
        if mask not in self.ACCESS_MASKS:
            mask = "0x1010"
        self.emit_telemetry(
            event_id=10,
            channel=WIN_SYSMON_OP,
            provider=WIN_SYSMON_PROVIDER,
            computer=self.agent.hostname,
            source_image="C:\\Windows\\System32\\svchost.exe",
            source_process_id=4424,
            target_image="C:\\Windows\\System32\\lsass.exe",
            target_process_id=668,
            granted_access=mask,
            rule_name="Technique",
            event_type="GrantedAccess",
            user=self.agent.user,
            details={
                "operation": "OPEN_PROCESS",
                "object": "lsass.exe",
                "access_strings": self._access_strings(mask),
            },
        )
        return AttackModuleResult(
            module="lsass_dump_access",
            technique_id="T1003.001",
            success=True,
            summary=f"Simulated ProcessAccess against lsass.exe ({mask})",
            details={"access_mask": mask, "target": "lsass.exe"},
            started_at=started,
            duration_ms=14.0,
        )

    @staticmethod
    def _access_strings(mask: str) -> list[str]:
        names: list[str] = []
        value = int(mask, 16)
        flags = {
            0x1000: "PROCESS_QUERY_LIMITED_INFORMATION",
            0x0400: "PROCESS_QUERY_INFORMATION",
            0x0010: "PROCESS_VM_READ",
            0x0020: "PROCESS_VM_WRITE",
            0x0008: "PROCESS_VM_OPERATION",
            0x00100000: "SYNCHRONIZE",
        }
        for bit, name in flags.items():
            if value & bit:
                names.append(name)
        return names

    def rollback(self) -> AttackModuleResult | None:
        return None


class DPAPIQuerySimulator(BaseModule):
    """T1003.001 — OS Credential Dumping (DPAPI).

    Emits a ProcessAccess telemetry record matching the pattern of a DPAPI
    blob decrypt attempt landing in ``lsass.exe``.
    """

    def validate(self) -> bool:
        context = str(self.parameters.get("context", "current_user"))
        return context in {"current_user", "local_machine"}

    def execute(self) -> AttackModuleResult:
        started = datetime.now(UTC)
        context = str(self.parameters.get("context", "current_user"))
        self.emit_telemetry(
            event_id=10,
            channel=WIN_SYSMON_OP,
            provider=WIN_SYSMON_PROVIDER,
            computer=self.agent.hostname,
            source_image="C:\\Windows\\System32\\dllhost.exe",
            source_process_id=2296,
            target_image="C:\\Windows\\System32\\lsass.exe",
            target_process_id=668,
            granted_access="0x1010",
            rule_name="DPAPI",
            event_type="GrantedAccess",
            user=self.agent.user,
            details={"context": context, "provider": "Microsoft__CryptProtect_DPAPI"},
        )
        return AttackModuleResult(
            module="dpapi_query",
            technique_id="T1003.001",
            success=True,
            summary=f"Simulated DPAPI {context} credential query",
            details={"context": context},
            started_at=started,
            duration_ms=9.0,
        )

    def rollback(self) -> AttackModuleResult | None:
        return None
