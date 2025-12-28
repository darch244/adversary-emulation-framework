"""Adversary emulation modules: safe, deterministic, in-memory simulation units."""

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

__all__ = [
    "AmsiPatchSimulator",
    "BaseModule",
    "DPAPIQuerySimulator",
    "LsassDumpAccessSimulator",
    "NetworkConnectionsModule",
    "ProcessHollowingTelemetry",
    "RegistryRunKeyModule",
    "SMBAdminShareSimulator",
    "ScheduledTaskModule",
    "SystemProfileModule",
    "UserEnumModule",
    "WMIPrivseDispatch",
]
