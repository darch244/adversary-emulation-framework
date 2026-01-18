"""End-to-end orchestration and beacon lifecycle tests.

Covers the full hermetic pipeline: registration -> tasking -> execution ->
telemetry submission — exercised over the ASGI listener via httpx so no
network socket is opened.
"""

from __future__ import annotations

import httpx
import pytest

from core.listener import apply_malleable_transform, build_listener, load_profile
from core.models import C2Task
from core.orchestrator import ModuleRegistryError


@pytest.mark.asyncio
async def test_beacon_registers_and_heartbeats(async_client):
    resp = await async_client.post(
        "/register",
        json={
            "hostname": "SIM-HOST-01",
            "user": "AEF\\simuser",
            "platform": "windows",
            "arch": "x86_64",
            "pid": 14141,
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "agent_id" in data
    assert "session_key_wrapped" in data

    resp2 = await async_client.post(
        "/task", json={"agent_id": data["agent_id"], "ts": 1.0}
    )
    assert resp2.status_code == 200
    assert resp2.json()["tasks"] == []


@pytest.mark.asyncio
async def test_full_beacon_lifecycle_hermetic():
    """Drive the platform without touching the network."""
    from agent.beacon import Beacon, BeaconConfig
    from core.crypto import RSACipher
    from core.orchestrator import Campaign
    from tests.conftest import DEFAULT_CHAINS

    campaign = Campaign.from_yaml(DEFAULT_CHAINS)
    rsa = RSACipher.generate()
    app = build_listener(rsa_cipher=rsa, campaign=campaign)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver"
    ) as client:
        beacon = Beacon(
            transport=client,
            config=BeaconConfig(
                hostname="SIM-HOST-01",
                user="AEF\\simuser",
                jitter=0.0,
            ),
        )
        # stage tasks before the beacon's loop begins via a direct orchestrator handle
        # (the listener owns its own orchestrator, so we re-stage through /task by
        # injecting via the app's internal state is not exposed — instead we drive
        # the beacon loop with a task_provider).
        tasks = [
            {
                "task_id": "task-0000000001",
                "module": "system_profile",
                "technique_id": "T1082",
                "parameters": {},
            },
            {
                "task_id": "task-0000000002",
                "module": "lsass_dump_access",
                "technique_id": "T1003.001",
                "parameters": {"access_mask": "0x1010"},
            },
        ]

        def provider():
            return tasks[beacon.tasks_completed :]

        await beacon.run(task_provider=provider)
        assert beacon.tasks_completed == 2
        assert all(r["success"] for r in beacon.results)


def test_orchestrator_stage_executes_all(registered_orchestrator, sample_agent):
    tasks = registered_orchestrator.stage_campaign(sample_agent.agent_id)
    assert len(tasks) == 11
    for task in tasks:
        result = registered_orchestrator.exec_module(
            task.module, sample_agent, task.parameters
        )
        assert result.success
        registered_orchestrator.complete_task(task.task_id, result)
    assert registered_orchestrator.results
    assert registered_orchestrator.telemetry is not None
    assert registered_orchestrator.telemetry.count > 0
    # Every emitted event must carry the technique id that produced it.
    for event in registered_orchestrator.telemetry.events:
        assert event.technique_id not in (None, "")


def test_orchestrator_tags_events_with_technique(registered_orchestrator, sample_agent):
    task = registered_orchestrator.stage_campaign(sample_agent.agent_id)[1]
    registered_orchestrator.exec_module(task.module, sample_agent, task.parameters)
    assert registered_orchestrator.telemetry is not None
    ids = {e.technique_id for e in registered_orchestrator.telemetry.events}
    assert ids and all(i == "T1087" for i in ids)


def test_pending_tasks_fifo(registered_orchestrator, sample_agent):
    registered_orchestrator.enqueue_task(
        C2Task(
            task_id="task-0000000001",
            agent_id=sample_agent.agent_id,
            module="system_profile",
            technique_id="T1082",
        )
    )
    registered_orchestrator.enqueue_task(
        C2Task(
            task_id="task-0000000002",
            agent_id=sample_agent.agent_id,
            module="user_enum",
            technique_id="T1087",
        )
    )
    pending = registered_orchestrator.pending_tasks(sample_agent.agent_id)
    assert [t.task_id for t in pending] == ["task-0000000001", "task-0000000002"]
    # Second fetch returns nothing (delivered tasks are not re-served).
    assert registered_orchestrator.pending_tasks(sample_agent.agent_id) == []


def test_unknown_agent_rejected(orchestrator):
    with pytest.raises(KeyError):
        orchestrator.stage_campaign("no-such-agent")


def test_unknown_module_raises(orchestrator, sample_agent):
    orchestrator.register_agent(sample_agent)
    with pytest.raises(ModuleRegistryError):
        orchestrator.exec_module("ghost_module", sample_agent, {})


def test_malleable_profile_loads():
    profile = load_profile("configs/c2_profile.yaml")
    assert profile["profile_name"] == "APT29-Simulated"
    assert "headers" in profile


def test_malleable_transform_adds_junk():
    profile = load_profile("configs/c2_profile.yaml")
    payload = {"agent_id": "abc"}
    transformed = apply_malleable_transform(payload, profile)
    assert "_junk_prefix" in transformed
    assert "_junk_suffix" in transformed
    assert transformed["agent_id"] == "abc"


@pytest.mark.asyncio
async def test_result_submission_records_telemetry(async_client):
    reg = await async_client.post(
        "/register",
        json={"hostname": "H", "user": "U", "pid": 1},
    )
    agent_id = reg.json()["agent_id"]
    resp = await async_client.post(
        "/result",
        json={
            "task_id": "task-0000000001",
            "agent_id": agent_id,
            "module": "system_profile",
            "technique_id": "T1082",
            "success": True,
            "summary": "ok",
            "telemetry": {
                "event_id": 1,
                "channel": "Microsoft-Windows-Sysmon/Operational",
                "provider": "Microsoft-Windows-Sysmon",
                "computer": "H",
                "image": "C:\\x.exe",
            },
        },
    )
    assert resp.status_code == 200
    assert resp.json() == {"status": "accepted"}
    summary = await async_client.get("/summary")
    assert summary.json()["events_emitted"] == 1
