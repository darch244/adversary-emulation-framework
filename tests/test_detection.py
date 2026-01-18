"""Sigma engine, detection matching, and coverage matrix tests."""

import pytest

from core.models import TelemetryEvent
from detection.matrix_reporter import MatrixReporter
from detection.sigma_engine import (
    ConditionParseError,
    SigmaEngine,
    SigmaRuleLoadError,
    compile_condition,
    match_selection,
)


@pytest.fixture
def engine() -> SigmaEngine:
    eng = SigmaEngine()
    eng.load_directory("detection/rules")
    return eng


class TestRuleLoading:
    def test_loads_three_rules(self, engine):
        assert len(engine.rules) == 3

    def test_rule_fields_bound(self, engine):
        wmi = next(r for r in engine.rules if "WMI" in r.title)
        assert wmi.tags and "attack.t1047" in wmi.tags
        assert wmi.level == "high"
        assert wmi.detection.condition == "selection and not filter_benign"

    def test_bad_yaml_raises(self, tmp_path):
        bad = tmp_path / "bad.yaml"
        bad.write_text(": : not a mapping", encoding="utf-8")
        with pytest.raises(SigmaRuleLoadError):
            SigmaEngine.from_yaml_file(bad)


class TestMatching:
    def test_wmi_rule_hits(self, engine, sample_events):
        event = sample_events[0]
        detections = engine.detect(event)
        wmi = next(d for d in detections if "WMI" in d.rule_title)
        assert wmi.matched

    def test_wmi_rule_misses_non_wmi(self, engine, sample_events):
        event = sample_events[1]  # lsass access, EventID 10
        detections = engine.detect(event)
        assert not any("WMI" in d.rule_title and d.matched for d in detections)

    def test_lsass_rule_hits(self, engine, sample_events):
        event = sample_events[1]
        detections = engine.detect(event)
        lsass = next(d for d in detections if "LSASS" in d.rule_title)
        assert lsass.matched

    def test_registry_rule_hits(self, engine, sample_events):
        event = sample_events[2]
        detections = engine.detect(event)
        runkey = next(d for d in detections if "Run Key" in d.rule_title)
        assert runkey.matched

    def test_filter_suppresses_benign_lsass(self, engine):
        event = TelemetryEvent(
            event_id=10,
            channel="Microsoft-Windows-Sysmon/Operational",
            provider="Microsoft-Windows-Sysmon",
            computer="X",
            source_image="C:\\Windows\\System32\\svchost.exe",
            target_image="C:\\Windows\\System32\\lsass.exe",
            granted_access="0x1010",
        )
        detections = engine.detect(event)
        lsass = next(d for d in detections if "LSASS" in d.rule_title)
        assert not lsass.matched  # filtered: svchost.exe source is benign


class TestConditionCompiler:
    def test_and_not(self):
        expr = compile_condition("selection and not filter")
        assert expr.eval({"selection": True, "filter": False}, ["selection", "filter"])
        assert not expr.eval(
            {"selection": True, "filter": True}, ["selection", "filter"]
        )

    def test_or(self):
        expr = compile_condition("selection_a or selection_b")
        assert expr.eval({"selection_a": False, "selection_b": True}, [])
        assert not expr.eval({"selection_a": False, "selection_b": False}, [])

    def test_one_of_glob(self):
        expr = compile_condition("1 of selection_*")
        assert expr.eval(
            {"selection_a": False, "selection_b": True}, ["selection_a", "selection_b"]
        )
        assert not expr.eval(
            {"selection_a": False, "selection_b": False}, ["selection_a", "selection_b"]
        )

    def test_one_of_them(self):
        expr = compile_condition("1 of them")
        assert expr.eval({"a": False, "b": True}, ["a", "b"])
        assert not expr.eval({"a": False, "b": False}, ["a", "b"])

    def test_all_of_glob(self):
        expr = compile_condition("all of selection_*")
        assert expr.eval(
            {"selection_a": True, "selection_b": True}, ["selection_a", "selection_b"]
        )
        assert not expr.eval(
            {"selection_a": True, "selection_b": False}, ["selection_a", "selection_b"]
        )

    def test_parentheses(self):
        expr = compile_condition("(a or b) and not c")
        assert expr.eval({"a": False, "b": True, "c": False}, [])
        assert not expr.eval({"a": False, "b": True, "c": True}, [])

    def test_malformed_raises(self):
        with pytest.raises(ConditionParseError):
            compile_condition("selection and")
        with pytest.raises(ConditionParseError):
            compile_condition("1 selection")


class TestModifiers:
    def test_contains(self):
        assert match_selection(
            {"CommandLine|contains": "whoami"},
            {"CommandLine": "net user then whoami /all"},
        )
        assert not match_selection(
            {"CommandLine|contains": "pwn"}, {"CommandLine": "whoami"}
        )

    def test_endswith(self):
        assert match_selection(
            {"Image|endswith": "lsass.exe"},
            {"Image": "C:\\Windows\\System32\\lsass.exe"},
        )
        assert not match_selection(
            {"Image|endswith": "lsass.exe"}, {"Image": "C:\\lsass_util.exe"}
        )

    def test_startswith(self):
        target = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\X"
        assert match_selection(
            {"TargetObject|startswith": "HKCU\\Software"},
            {"TargetObject": target},
        )
        assert not match_selection(
            {"TargetObject|startswith": "HKLM"}, {"TargetObject": "HKCU\\Software"}
        )

    def test_cased(self):
        assert not match_selection(
            {"Image|endswith|cased": "Lsass.EXE"}, {"Image": "C:\\lsass.exe"}
        )

    def test_exists(self):
        assert match_selection({"Image|exists": True}, {"Image": "C:\\x.exe"})
        assert not match_selection({"Image|exists": True}, {"Other": "y"})


class TestMatrixReporter:
    def test_matrix_builds_gaps(self):
        reporter = MatrixReporter()
        simulated = [("T1003.001", "lsass_dump_access"), ("T1082", "system_profile")]
        matched = {"T1003.001": {"rule-1"}}
        matrix = reporter.build(simulated, matched)
        assert matrix.total == 2
        assert matrix.covered_count == 1
        assert matrix.uncovered_count == 1

    def test_markdown_render(self):
        reporter = MatrixReporter()
        matrix = reporter.build([("T1082", "system_profile")], {"T1082": {"r"}})
        md = reporter.render_markdown(matrix)
        assert "T1082" in md
        assert "Coverage" in md

    def test_json_render(self):
        reporter = MatrixReporter()
        matrix = reporter.build([], {})
        payload = matrix.to_json()
        assert '"techniques"' in payload


class TestDetectionEdgecases:
    def test_rule_without_id(self):
        raw = {
            "title": "No ID rule",
            "detection": {
                "selection": {"EventID": 1},
                "condition": "selection",
            },
        }
        rule = SigmaEngine._rule_from_mapping(raw)
        assert rule.name == "untitled"

    def test_array_values_or_semantics(self):
        selection = {"EventID": [1, 3, 7]}
        assert match_selection(selection, {"EventID": "3"})
        assert not match_selection(selection, {"EventID": "11"})
