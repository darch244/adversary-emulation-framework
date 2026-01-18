"""Telemetry generation and schema conformance tests."""

from datetime import UTC, datetime


class TestSyntheticLogger:
    def test_emit_counts(self, telemetry_logger):
        before = datetime.now(UTC)
        telemetry_logger.emit_process_create(
            image="C:\\Windows\\System32\\cmd.exe",
            command_line="whoami",
            user="AEF\\u",
            pid=100,
        )
        assert telemetry_logger.count == 1
        assert telemetry_logger.since(before) == telemetry_logger.events

    def test_clear(self, telemetry_logger):
        telemetry_logger.emit_registry_value_set(
            image="C:\\reg.exe",
            target_object="HKLM\\SOFTWARE\\X\\Y",
            value_data="v",
        )
        telemetry_logger.clear()
        assert telemetry_logger.count == 0

    def test_event_1_schema(self, telemetry_logger):
        event = telemetry_logger.emit_process_create(
            image="C:\\Windows\\System32\\schtasks.exe",
            command_line="/create /tn T /tr X",
            user="AEF\\u",
            pid=101,
            parent_pid=50,
        )
        assert event.event_id == 1
        payload = event.to_eventlog_dict()
        assert payload["System.EventID"] == 1
        assert "EventData.Image" in payload
        assert "EventData.CommandLine" in payload

    def test_event_3_has_dst(self, telemetry_logger):
        event = telemetry_logger.emit_network_connection(
            image="C:\\svc.exe",
            destination_ip="10.0.0.5",
            destination_port=445,
        )
        payload = event.to_eventlog_dict()
        assert payload["EventData.DestinationIp"] == "10.0.0.5"
        assert payload["EventData.DestinationPort"] == 445

    def test_event_10_access_mask(self, telemetry_logger):
        event = telemetry_logger.emit_process_access(
            source_image="C:\\svchost.exe",
            target_image="C:\\Windows\\System32\\lsass.exe",
            granted_access="0x1010",
        )
        assert event.flat_dict["GrantedAccess"] == "0x1010"
        assert event.flat_dict["TargetImage"] == "C:\\Windows\\System32\\lsass.exe"
        assert event.flat_dict["SourceImage"] == "C:\\svchost.exe"

    def test_event_13_registry(self, telemetry_logger):
        target = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Bad"
        event = telemetry_logger.emit_registry_value_set(
            image="C:\\reg.exe", target_object=target, value_data="x"
        )
        assert event.flat_dict["TargetObject"] == target


class TestTelemetryEventModel:
    def test_flat_dict_contains_field_mappings(self, sample_events):
        _, ev10, ev13 = sample_events
        assert ev10.flat_dict["EventID"] == "10"
        assert ev10.flat_dict["TargetImage"].endswith("lsass.exe")
        assert ev13.flat_dict["TargetObject"] != ""

    def test_eventlog_dict_roundtrip(self, sample_events):
        ev1, _, _ = sample_events
        payload = ev1.to_eventlog_dict()
        assert payload["System.EventID"] == 1
        assert isinstance(payload["System.TimeCreated.SystemTime"], str)

    def test_parent_process_id_alias(self, sample_events):
        ev1, _, _ = sample_events
        assert ev1.parent_process_id is ev1.source_process_id
