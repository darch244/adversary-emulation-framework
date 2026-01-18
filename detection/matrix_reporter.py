"""Detection gap analyzer producing ATT&CK-coverage Markdown and JSON matrices."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class CoverageGap:
    """A single simulated technique with its detection state."""

    technique_id: str
    technique_name: str
    tactic: str
    simulated: bool
    detected: bool
    rule_id: str | None = None
    rule_title: str | None = None
    events_emitted: int = 0

    @property
    def covered(self) -> bool:
        return self.simulated and self.detected


@dataclass
class DetectionMatrix:
    """Aggregated coverage output."""

    gaps: list[CoverageGap] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.gaps)

    @property
    def covered_count(self) -> int:
        return sum(1 for g in self.gaps if g.covered)

    @property
    def uncovered_count(self) -> int:
        return sum(1 for g in self.gaps if g.simulated and not g.detected)

    def coverage_ratio(self) -> float:
        simulated = sum(1 for g in self.gaps if g.simulated)
        if simulated == 0:
            return 0.0
        return self.covered_count / simulated

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_techniques": self.total,
            "covered": self.covered_count,
            "uncovered": self.uncovered_count,
            "coverage_ratio": round(self.coverage_ratio(), 4),
            "techniques": [asdict(g) for g in self.gaps],
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, sort_keys=True)


class MatrixReporter:
    """Builds a ``DetectionMatrix`` from sim results and Sigma matches."""

    def __init__(self) -> None:
        self.technique_meta: dict[str, dict[str, str]] = {
            "T1082": {
                "name": "System Information Discovery",
                "tactic": "Discovery",
            },
            "T1087": {
                "name": "Account Discovery",
                "tactic": "Discovery",
            },
            "T1049": {
                "name": "System Network Connections Discovery",
                "tactic": "Discovery",
            },
            "T1003.001": {
                "name": "LSASS Memory",
                "tactic": "Credential Access",
            },
            "T1047": {
                "name": "Windows Management Instrumentation",
                "tactic": "Lateral Movement",
            },
            "T1021.002": {
                "name": "SMB/Windows Admin Shares",
                "tactic": "Lateral Movement",
            },
            "T1547.001": {
                "name": "Registry Run Keys / Startup Folder",
                "tactic": "Persistence",
            },
            "T1053.005": {
                "name": "Scheduled Task",
                "tactic": "Persistence",
            },
            "T1562.001": {
                "name": "Disable or Modify Tools",
                "tactic": "Defense Evasion",
            },
            "T1055": {
                "name": "Process Injection",
                "tactic": "Defense Evasion",
            },
        }

    def build(
        self,
        simulated_techniques: list[tuple[str, str]],
        matched_rules: dict[str, set[str]],
        events_by_technique: dict[str, int] | None = None,
        rule_titles: dict[str, str] | None = None,
    ) -> DetectionMatrix:
        """Aggregate simulated techniques against the rules that matched them.

        ``simulated_techniques`` is a list of ``(technique_id, module_name)``.
        ``matched_rules`` maps ``technique_id -> {rule_id, ...}``.
        ``rule_titles`` maps ``rule_id -> title`` for reporting.
        """
        rule_titles = rule_titles or {}
        events_by_technique = events_by_technique or {}
        gaps: list[CoverageGap] = []
        for technique_id, _module in simulated_techniques:
            meta = self.technique_meta.get(technique_id, {})
            rules = sorted(matched_rules.get(technique_id, set()))
            gaps.append(
                CoverageGap(
                    technique_id=technique_id,
                    technique_name=meta.get("name", technique_id),
                    tactic=meta.get("tactic", "Unknown"),
                    simulated=True,
                    detected=bool(rules),
                    rule_id=rules[0] if rules else None,
                    rule_title=rule_titles.get(rules[0]) if rules else None,
                    events_emitted=events_by_technique.get(technique_id, 0),
                )
            )
        return DetectionMatrix(gaps=gaps)

    def render_markdown(self, matrix: DetectionMatrix) -> str:
        """Render the coverage matrix as an executive Markdown table."""
        lines = [
            "# ATT&CK Detection Coverage Matrix",
            "",
            "| Technique | Tactic | Simulated | Detected | Sigma Rule |",
            "|---|---|---|---|---|",
        ]
        for gap in matrix.gaps:
            sim = "yes" if gap.simulated else "no"
            det = "yes" if gap.detected else "no"
            if gap.rule_title:
                rule = f"{gap.rule_id} — {gap.rule_title}"
            elif gap.rule_id:
                rule = gap.rule_id
            else:
                rule = "-"
            lines.append(
                f"| {gap.technique_id} ({gap.technique_name}) | {gap.tactic} "
                f"| {sim} | {det} | {rule} |"
            )
        lines.extend(
            [
                "",
                (
                    f"**Coverage: {matrix.covered_count}/{matrix.total} "
                    f"({matrix.coverage_ratio():.1%})**"
                ),
                "",
                "_Generated by adversary-emulation-framework._",
            ]
        )
        return "\n".join(lines)

    def render_json(self, matrix: DetectionMatrix) -> str:
        return matrix.to_json()
