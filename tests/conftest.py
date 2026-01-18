"""Shared fixtures and mock transports for the test suite."""

from __future__ import annotations

from collections.abc import AsyncGenerator
from pathlib import Path

import httpx
import pytest
import pytest_asyncio

from core.crypto import AESCipher, RSACipher
from core.models import Agent, TelemetryEvent
from core.orchestrator import Campaign, Orchestrator
from detection.telemetry_logger import SyntheticTelemetryLogger

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PROFILE = REPO_ROOT / "configs" / "c2_profile.yaml"
DEFAULT_CHAINS = REPO_ROOT / "configs" / "attack_chains.yaml"
DEFAULT_RULES = REPO_ROOT / "detection" / "rules"


@pytest.fixture
def rsa_cipher() -> RSACipher:
    return RSACipher.generate()


@pytest.fixture
def sample_agent() -> Agent:
    return Agent(
        agent_id="test-agent-0001",
        hostname="SIM-HOST-01",
        user="AEF\\simuser",
        platform="windows",
        arch="x86_64",
        pid=14141,
    )


@pytest.fixture
def campaign() -> Campaign:
    return Campaign.from_yaml(DEFAULT_CHAINS)


@pytest.fixture
def telemetry_logger() -> SyntheticTelemetryLogger:
    return SyntheticTelemetryLogger(computer="TEST-BOX")


@pytest.fixture
def orchestrator(rsa_cipher: RSACipher, campaign: Campaign) -> Orchestrator:
    telemetry = SyntheticTelemetryLogger(computer="TEST-BOX")
    return Orchestrator(campaign=campaign, rsa_cipher=rsa_cipher, telemetry=telemetry)


@pytest.fixture
def registered_orchestrator(
    orchestrator: Orchestrator, sample_agent: Agent
) -> Orchestrator:
    orchestrator.register_agent(sample_agent)
    return orchestrator


@pytest.fixture
def aes_cipher() -> AESCipher:
    return AESCipher(key=b"\x01" * 32)


@pytest.fixture
def sample_events() -> list[TelemetryEvent]:
    return [
        TelemetryEvent(
            event_id=1,
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            computer="SIM-HOST-01",
            image="C:\\Windows\\System32\\wmiprvse.exe",
            command_line="whoami /all",
            user="AEF\\simuser",
            process_id=2020,
        ),
        TelemetryEvent(
            event_id=10,
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            computer="SIM-HOST-01",
            source_image="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            source_process_id=4424,
            target_image="C:\\Windows\\System32\\lsass.exe",
            target_process_id=668,
            granted_access="0x1010",
        ),
        TelemetryEvent(
            event_id=13,
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            computer="SIM-HOST-01",
            image="C:\\Windows\\System32\\reg.exe",
            new_key_name="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\AEFSimulationUpdate",
            target_object="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\AEFSimulationUpdate",
            process_id=1900,
            user="AEF\\simuser",
        ),
    ]


@pytest_asyncio.fixture
async def async_client() -> AsyncGenerator[httpx.AsyncClient, None]:
    from core.crypto import RSACipher

    rsa = RSACipher.generate()
    from core.listener import build_listener
    from core.orchestrator import Campaign

    campaign = Campaign(campaign_name="test", campaign_id="T-001", description="test")
    app = build_listener(rsa_cipher=rsa, campaign=campaign)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver"
    ) as client:
        yield client
