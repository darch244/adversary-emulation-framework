"""Unit tests for adversary emulation modules."""

from __future__ import annotations

import pytest

from agent.executor import ModuleExecutor, UnknownModuleError
from core.models import Agent
from modules.credential_access import DPAPIQuerySimulator, LsassDumpAccessSimulator
from modules.discovery import (
    NetworkConnectionsModule,
    SystemProfileModule,
    UserEnumModule,
)
from modules.evasion import AmsiPatchSimulator, ProcessHollowingTelemetry
from modules.lateral_movement import SMBAdminShareSimulator, WMIPrivseDispatch
from modules.persistence import RegistryRunKeyModule, ScheduledTaskModule


@pytest.fixture
def sim_agent() -> Agent:
    return Agent(
        agent_id="test-mod-001", hostname="TEST-HOST", user="AEF\\test", pid=9999
    )


# ── Discovery ────────────────────────────────────────────────────────────────


class TestSystemProfile:
    def test_validate_passes(self, sim_agent):
        assert SystemProfileModule(agent=sim_agent).validate()

    def test_execute_emits_event_1(self, sim_agent):
        mod = SystemProfileModule(agent=sim_agent)
        result = mod.execute()
        assert result.success
        assert result.technique_id == "T1082"
        assert len(mod.telemetry_events) == 1
        assert mod.telemetry_events[0].event_id == 1

    def test_returns_none_rollback(self, sim_agent):
        assert RegistryRunKeyModule(agent=sim_agent).rollback() is not None


class TestUserEnum:
    def test_execute_with_domain(self, sim_agent):
        mod = UserEnumModule(agent=sim_agent, parameters={"include_domain": True})
        result = mod.execute()
        assert result.success and "domain_users" in result.details
        assert len(result.details["domain_users"]) > 0

    def test_execute_without_domain(self, sim_agent):
        mod = UserEnumModule(agent=sim_agent, parameters={"include_domain": False})
        result = mod.execute()
        assert "domain_users" in result.details


class TestNetworkConnections:
    def test_execute_event_3(self, sim_agent):
        mod = NetworkConnectionsModule(agent=sim_agent)
        result = mod.execute()
        assert result.success and result.technique_id == "T1049"
        assert mod.telemetry_events[0].event_id == 3


# ── Credential Access ────────────────────────────────────────────────────────


class TestLsassAccess:
    def test_valid_mask_1010(self, sim_agent):
        mod = LsassDumpAccessSimulator(
            agent=sim_agent, parameters={"access_mask": "0x1010"}
        )
        assert mod.validate()
        result = mod.execute()
        assert result.success and mod.telemetry_events[0].event_id == 10

    def test_valid_mask_1438(self, sim_agent):
        mod = LsassDumpAccessSimulator(
            agent=sim_agent, parameters={"access_mask": "0x1438"}
        )
        assert mod.validate()

    def test_invalid_mask(self, sim_agent):
        mod = LsassDumpAccessSimulator(
            agent=sim_agent, parameters={"access_mask": "0xDEAD"}
        )
        assert not mod.validate()


class TestDPAPI:
    def test_valid_context(self, sim_agent):
        assert DPAPIQuerySimulator(
            agent=sim_agent, parameters={"context": "local_machine"}
        ).validate()

    def test_invalid_context(self, sim_agent):
        mod = DPAPIQuerySimulator(agent=sim_agent, parameters={"context": "other"})
        assert not mod.validate()


# ── Lateral Movement ─────────────────────────────────────────────────────────


class TestWMI:
    def test_execute(self, sim_agent):
        mod = WMIPrivseDispatch(agent=sim_agent, parameters={"command": "net user"})
        result = mod.execute()
        assert "WmiPrvSE.exe" in result.summary


class TestSMB:
    def test_execute(self, sim_agent):
        mod = SMBAdminShareSimulator(
            agent=sim_agent, parameters={"target_host": "DC.corp"}
        )
        result = mod.execute()
        assert "ADMIN$" in result.summary


# ── Persistence ──────────────────────────────────────────────────────────────


class TestRegistryRunKey:
    def test_execute_event_13(self, sim_agent):
        mod = RegistryRunKeyModule(agent=sim_agent)
        assert mod.validate()
        result = mod.execute()
        assert result.success and mod.telemetry_events[0].event_id == 13

    def test_rollback(self, sim_agent):
        mod = RegistryRunKeyModule(agent=sim_agent)
        mod.execute()
        rb = mod.rollback()
        assert rb is not None and rb.rolled_back is True


class TestScheduledTask:
    def test_execute_emits_two_events(self, sim_agent):
        mod = ScheduledTaskModule(agent=sim_agent, parameters={"task_name": "AEFTest"})
        result = mod.execute()
        assert result.success and len(mod.telemetry_events) == 2

    def test_rollback_idempotent(self, sim_agent):
        mod = ScheduledTaskModule(agent=sim_agent)
        mod.execute()
        rb1 = mod.rollback()
        rb2 = mod.rollback()
        assert rb1 is not None
        assert rb2 is None  # second call returns None


# ── Evasion ──────────────────────────────────────────────────────────────────


class TestAMSI:
    def test_execute_two_events(self, sim_agent):
        mod = AmsiPatchSimulator(agent=sim_agent)
        assert mod.validate()
        result = mod.execute()
        assert result.success and len(mod.telemetry_events) == 2

    def test_invalid_subsystem(self, sim_agent):
        assert not AmsiPatchSimulator(
            agent=sim_agent, parameters={"subsystem": "nope"}
        ).validate()


class TestHollowing:
    def test_execute(self, sim_agent):
        mod = ProcessHollowingTelemetry(agent=sim_agent)
        assert mod.validate()
        result = mod.execute()
        assert result.success and len(mod.telemetry_events) == 2

    def test_invalid_template(self, sim_agent):
        mod = ProcessHollowingTelemetry(
            agent=sim_agent, parameters={"template_process": "foo.txt"}
        )
        assert not mod.validate()


# ── Executor ──────────────────────────────────────────────────────────────────


class TestModuleExecutor:
    def test_runs_all_registered(self, sim_agent):
        names = list(ModuleExecutor._REGISTRY.keys())
        assert len(names) == 11
        for name in names:
            executor = ModuleExecutor(module_name=name, agent=sim_agent, parameters={})
            result = executor.run()
            assert result.success, f"{name} failed"

    def test_unknown_module(self, sim_agent):
        with pytest.raises(UnknownModuleError):
            executor = ModuleExecutor(module_name="does_not_exist", agent=sim_agent)
            executor.run()
