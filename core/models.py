"""Pydantic v2 domain schemas for the adversary-emulation framework."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field, field_validator


class AgentStatus(StrEnum):
    DISCOVERED = "discovered"
    REGISTERED = "registered"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    LOST = "lost"


class Agent(BaseModel):
    """A simulated implant registered against the C2 listener."""

    agent_id: str = Field(min_length=8, max_length=64)
    hostname: str = Field(min_length=1, max_length=255)
    user: str = Field(min_length=1, max_length=255)
    platform: str = "windows"
    arch: str = "x86_64"
    pid: int = 0
    session_key_wrapped: bytes | None = None
    status: AgentStatus = AgentStatus.DISCOVERED
    first_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_seen: datetime = Field(default_factory=lambda: datetime.now(UTC))
    task_queue_size: int = 0


class C2TaskStatus(StrEnum):
    PENDING = "pending"
    DELIVERED = "delivered"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class C2Task(BaseModel):
    """A task routed from the listener to an implanted beacon."""

    task_id: str = Field(min_length=8, max_length=64)
    agent_id: str = Field(min_length=8, max_length=64)
    module: str = Field(min_length=1, max_length=128)
    technique_id: str = Field(min_length=1, max_length=16)
    parameters: dict[str, Any] = Field(default_factory=dict)
    status: C2TaskStatus = C2TaskStatus.PENDING
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    executed_at: datetime | None = None
    completed_at: datetime | None = None


class AttackModuleResult(BaseModel):
    """Structured result produced by a BaseModule execution."""

    module: str
    technique_id: str
    success: bool
    summary: str
    details: dict[str, Any] = Field(default_factory=dict)
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    duration_ms: float = 0.0
    rolled_back: bool = False

    @field_validator("summary")
    @classmethod
    def summary_nonempty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("summary must not be empty")
        return v.strip()


class TelemetryEvent(BaseModel):
    """A synthetic Windows Security / Sysmon event.

    Matches the canonical Microsoft event payload schema (System/EventData).
    """

    event_id: int
    channel: str
    provider: str
    computer: str
    time_created: datetime = Field(default_factory=lambda: datetime.now(UTC))
    process_guid: str | None = None
    process_id: int | None = None
    technique_id: str | None = None
    image: str | None = None
    target_image: str | None = None
    target_process_id: int | None = None
    source_process_id: int | None = None
    source_image: str | None = None
    granted_access: str | None = None
    rule_name: str | None = None
    event_type: str | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    source_ip: str | None = None
    user: str | None = None
    command_line: str | None = None
    target_object: str | None = None
    new_key_name: str | None = None
    task_name: str | None = None
    hashes: str | None = None
    integrity_level: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)

    def to_eventlog_dict(self) -> dict[str, Any]:
        """Serialize into the flattened Microsoft event-data dictionary shape."""
        payload: dict[str, Any] = {
            "System.EventID": self.event_id,
            "System.Channel": self.channel,
            "System.Provider": self.provider,
            "System.Computer": self.computer,
            "System.TimeCreated.SystemTime": self.time_created.isoformat(),
            "EventData.Image": self.image or "",
            "EventData.CommandLine": self.command_line or "",
            "EventData.User": self.user or "",
            "EventData.ParentProcessId": self.process_id or 0,
            "EventData.ProcessId": self.process_id or 0,
        }
        if self.destination_ip is not None:
            payload["EventData.DestinationIp"] = self.destination_ip
        if self.destination_port is not None:
            payload["EventData.DestinationPort"] = self.destination_port
        if self.granted_access is not None:
            payload["EventData.GrantedAccess"] = self.granted_access
        if self.source_image is not None:
            payload["EventData.SourceImage"] = self.source_image
        if self.target_object is not None:
            payload["EventData.TargetObject"] = self.target_object
        if self.new_key_name is not None:
            payload["EventData.TargetObject"] = self.new_key_name
        if self.task_name is not None:
            payload["EventData.TaskName"] = self.task_name
        if self.target_image is not None:
            payload["EventData.TargetImage"] = self.target_image
        if self.target_process_id is not None:
            payload["EventData.TargetProcessId"] = self.target_process_id
        if self.source_process_id is not None:
            payload["EventData.SourceProcessId"] = self.source_process_id
        if self.technique_id is not None:
            payload["EventData.TechniqueId"] = self.technique_id
        payload.update(self.details)
        return payload

    @property
    def flat_dict(self) -> dict[str, Any]:
        """Alphanumeric key lookup map used by the Sigma engine's field access."""
        result: dict[str, Any] = {}
        if self.image is not None:
            result["Image"] = self.image
        if self.command_line is not None:
            result["CommandLine"] = self.command_line
        if self.user is not None:
            result["User"] = self.user
        if self.process_id is not None:
            result["ProcessId"] = str(self.process_id)
        if self.parent_process_id is not None:
            result["ParentProcessId"] = str(self.parent_process_id)
        if self.destination_ip is not None:
            result["DestinationIp"] = self.destination_ip
        if self.destination_port is not None:
            result["DestinationPort"] = str(self.destination_port)
        if self.granted_access is not None:
            result["GrantedAccess"] = self.granted_access
        if self.target_object is None and self.new_key_name is not None:
            result["TargetObject"] = self.new_key_name
        elif self.target_object is not None:
            result["TargetObject"] = self.target_object
        if self.task_name is not None:
            result["TaskName"] = self.task_name
        if self.rule_name is not None:
            result["RuleName"] = self.rule_name
        if self.event_type is not None:
            result["EventType"] = self.event_type
        if self.event_id:
            result["EventID"] = str(self.event_id)
        if self.target_image is not None:
            result["TargetImage"] = self.target_image
        if self.source_image is not None:
            result["SourceImage"] = self.source_image
        result.update({k: str(v) for k, v in self.details.items()})
        return result

    @property
    def parent_process_id(self) -> int | None:
        """Alias to keep Sigma `ParentProcessId` access consistent."""
        return self.source_process_id


class SigmaRuleStatus(StrEnum):
    STABLE = "stable"
    EXPERIMENTAL = "experimental"
    TEST = "test"
    DEPRECATED = "deprecated"
    UNSUPPORTED = "unsupported"


class SigmaRuleDetection(BaseModel):
    """The ``detection`` clause of a Sigma rule.

    Holds one or more named selections plus the boolean ``condition`` string.
    """

    selections: dict[str, dict[str, Any]] = Field(default_factory=dict)
    condition: str = ""


class SigmaRule(BaseModel):
    """Parsed in-memory representation of a SigmaHQ YAML detection rule."""

    title: str
    id_or_name: str
    status: SigmaRuleStatus = SigmaRuleStatus.STABLE
    description: str = ""
    references: list[str] = Field(default_factory=list)
    author: str = ""
    tags: list[str] = Field(default_factory=list)
    logsource: dict[str, str] = Field(default_factory=dict)
    detection: SigmaRuleDetection = Field(default_factory=SigmaRuleDetection)
    level: str = "informational"
    fields: list[str] = Field(default_factory=list)
    falsepositives: list[str] = Field(default_factory=list)

    @property
    def name(self) -> str:
        return self.id_or_name


class DetectionEvent(BaseModel):
    """Outcome of running a Sigma rule against a synthetic telemetry event."""

    rule_id: str
    rule_title: str
    matched: bool
    event_id: int = 0
    confidence: float = 0.0
    matched_selections: list[str] = Field(default_factory=list)
