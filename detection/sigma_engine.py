"""Native Sigma rule parser and detection matcher.

Implements the core SigmaHQ semantics required for the platform:

* YAML rule parsing onto the ``SigmaRule`` schema (logsource, detection,
  level, tags).
* Field transforms through Sigma modifiers: ``contains``, ``startswith``,
  ``endswith``, ``re``, ``exists``, ``cased``, ``base64offset``, ``utf16*``.
* Condition evaluation supporting ``and`` / ``or`` / ``not``, parentheses,
  ``N of selection*`` globs, and ``N of them``.

No network access is ever performed — matching is purely in-process.
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from core.models import (
    DetectionEvent,
    SigmaRule,
    SigmaRuleDetection,
    SigmaRuleStatus,
    TelemetryEvent,
)


class SigmaRuleLoadError(Exception):
    """Raised when a Sigma YAML rule cannot be parsed or validated."""


class ConditionParseError(Exception):
    """Raised when a ``condition`` string is malformed."""


@dataclass
class SigmaMatch:
    """Outcome of evaluating one rule against one telemetry event."""

    matched: bool
    matched_selections: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Selection-value matching
# ---------------------------------------------------------------------------

_CASED = "cased"

_CASE_VARIANTS: dict[str, list[str]] = {
    "utf16": ["utf16le", "utf16be"],
    "utf16le": ["utf16le"],
    "utf16be": ["utf16be"],
    "wide": ["utf16le"],
}


def _to_candidates(expected: str, modifiers: set[str]) -> list[str]:
    """Expand a value into candidate strings honoring encoding variants.

    Supports ASCII (default) plus UTF-16 encodings and ``base64offset``,
    which appends base64 representations of the value at byte offsets 0-2.
    """
    encodings: list[str] = ["ascii"]
    for mod in ("utf16", "utf16le", "utf16be", "wide"):
        if mod in modifiers:
            encodings = _CASE_VARIANTS[mod]
            break
    candidates: list[str] = []
    for enc in encodings:
        if enc == "ascii":
            candidates.append(expected)
        elif enc == "utf16le":
            candidates.append(expected.encode("utf-16-le").decode("latin-1"))
        elif enc == "utf16be":
            candidates.append(expected.encode("utf-16-be").decode("latin-1"))
    if "base64offset" in modifiers:
        for cand in list(candidates):
            for offset in range(3):
                padded = (
                    b"\x00" * offset + cand.encode("latin-1") + b"\x00" * (2 - offset)
                )
                candidates.append(base64.b64encode(padded).decode())
    return candidates


def _split_modifiers(field: str) -> tuple[str, set[str]]:
    parts = field.split("|")
    return parts[0], set(parts[1:])


def match_selection(
    selection: dict[str, Any],
    event_map: dict[str, str],
) -> bool:
    """Evaluate a single Sigma selection (map of field -> value spec)."""
    for raw_field, raw_value in selection.items():
        base_field, modifiers = _split_modifiers(raw_field)

        if base_field == "keywords":
            if not _matches_keywords(raw_value, event_map, modifiers):
                return False
            continue

        actual = event_map.get(base_field)

        if "exists" in modifiers:
            if (actual is not None) != bool(raw_value):
                return False
            continue

        if actual is None:
            return False
        if not _value_matches(actual, raw_value, modifiers):
            return False
    return True


def _matches_keywords(
    keyword_values: Any, event_map: dict[str, str], modifiers: set[str]
) -> bool:
    values = keyword_values if isinstance(keyword_values, list) else [keyword_values]
    haystack = " ".join(str(v) for v in event_map.values())
    return all(_single_matches(haystack, value, modifiers) for value in values)


def _value_matches(actual: str, spec: Any, modifiers: set[str]) -> bool:
    if isinstance(spec, dict):
        return all(
            _single_matches(actual, sub_value, modifiers)
            for _sub_key, sub_value in spec.items()
        )
    if isinstance(spec, list):
        return any(_single_matches(actual, item, modifiers) for item in spec)
    return _single_matches(actual, spec, modifiers)


def _single_matches(actual: str, expected: Any, modifiers: set[str]) -> bool:
    """Match one expected value against one actual field string."""
    if expected is None:
        return actual == ""

    case_sensitive = _CASED in modifiers
    haystack = actual if case_sensitive else actual.lower()
    norm_expected = expected if isinstance(expected, str) else str(expected)
    candidates = _to_candidates(norm_expected, modifiers)

    if "contains" in modifiers:
        probes = candidates if case_sensitive else [c.lower() for c in candidates]
        return any(p in haystack for p in probes)
    if "startswith" in modifiers:
        probes = candidates if case_sensitive else [c.lower() for c in candidates]
        return any(haystack.startswith(p) for p in probes)
    if "endswith" in modifiers:
        probes = candidates if case_sensitive else [c.lower() for c in candidates]
        return any(haystack.endswith(p) for p in probes)
    if "re" in modifiers:
        flags = 0 if case_sensitive else re.IGNORECASE
        return any(re.search(pattern, actual, flags) for pattern in candidates)

    if "*" in norm_expected or "?" in norm_expected:
        regex = _glob_to_regex(norm_expected, case_sensitive)
        return re.search(regex, actual) is not None
    if case_sensitive:
        return actual == norm_expected
    return actual.lower() == norm_expected.lower()


def _glob_to_regex(pattern: str, case_sensitive: bool) -> str:
    """Convert a Sigma glob (``*`` / ``?``) into an anchored regex."""
    escaped: list[str] = []
    for ch in pattern:
        if ch == "*":
            escaped.append(".*")
        elif ch == "?":
            escaped.append(".")
        else:
            escaped.append(re.escape(ch))
    prefix = "" if case_sensitive else "(?i)"
    return f"^{prefix}{''.join(escaped)}$"


# ---------------------------------------------------------------------------
# Condition expression compiler
# ---------------------------------------------------------------------------

_TOKENIZE_RE = re.compile(
    r"\s*(\(|\)|\bnot\b|\band\b|\bor\b|\bof\b|\d+|[A-Za-z_][A-Za-z0-9._*?]*)"
)


@dataclass
class _Expr:
    """Compiled condition; evaluates against a selection-name->bool map."""

    node: Any

    def eval(self, results: dict[str, bool], order: list[str]) -> bool:
        return _eval_node(self.node, results, order)


def _eval_node(node: Any, results: dict[str, bool], order: list[str]) -> bool:
    kind = node[0]
    if kind == "bool":
        return bool(node[1])
    if kind == "name":
        name = node[1]
        if name == "them":
            if not order:
                return False
            return results[order[0]]
        return bool(results.get(name, False))
    if kind == "not":
        return not _eval_node(node[1], results, order)
    if kind == "and":
        return _eval_node(node[1], results, order) and _eval_node(
            node[2], results, order
        )
    if kind == "or":
        return _eval_node(node[1], results, order) or _eval_node(
            node[2], results, order
        )
    if kind == "count_of":
        count = node[1]  # int, or None meaning "all must match"
        pattern = node[2]
        if pattern == "them":
            names = list(order)
        else:
            names = [n for n in order if _glob_match(pattern, n)]
        matched = sum(1 for n in names if results.get(n, False))
        if count is None:
            return bool(names) and matched == len(names)
        return matched >= count
    raise ConditionParseError(f"unknown node kind {kind!r}")


def _glob_match(pattern: str, name: str) -> bool:
    regex = _glob_to_regex(pattern, case_sensitive=True)
    return re.fullmatch(regex, name) is not None


def compile_condition(condition: str) -> _Expr:
    """Parse a Sigma condition string into an evaluable tree."""
    tokens = [t for t in _TOKENIZE_RE.findall(condition) if t]
    if not tokens:
        raise ConditionParseError("empty condition")
    pos = 0

    def peek() -> str | None:
        return tokens[pos] if pos < len(tokens) else None

    def advance() -> str:
        nonlocal pos
        token = peek()
        if token is None:
            raise ConditionParseError("unexpected end of condition")
        pos += 1
        return token

    def parse_or() -> Any:
        left = parse_and()
        while peek() == "or":
            advance()
            right = parse_and()
            left = ("or", left, right)
        return left

    def parse_and() -> Any:
        left = parse_unary()
        while peek() == "and":
            advance()
            right = parse_unary()
            left = ("and", left, right)
        return left

    def parse_unary() -> Any:
        if peek() == "not":
            advance()
            return ("not", parse_unary())
        return parse_primary()

    def parse_primary() -> Any:
        token = peek()
        if token is None:
            raise ConditionParseError("unexpected end of condition")
        if token == "(":
            advance()
            expr = parse_or()
            if advance() != ")":
                raise ConditionParseError("missing closing parenthesis")
            return expr
        if token.isdigit():
            advance()
            numeric_count = int(token)
            if advance() != "of":
                raise ConditionParseError("expected 'of' after count")
            pattern = advance()
            return ("count_of", numeric_count, pattern)
        if token in {"all", "any"}:
            keyword = token
            advance()
            if advance() != "of":
                raise ConditionParseError(f"expected 'of' after '{keyword}'")
            pattern = advance()
            quantifier: int | None = None if keyword == "all" else 1
            return ("count_of", quantifier, pattern)
        advance()
        if token in {"and", "or", "not", "of"}:
            raise ConditionParseError(f"unexpected keyword '{token}'")
        return ("name", token)

    expr = parse_or()
    if pos != len(tokens):
        raise ConditionParseError(f"unexpected trailing tokens near '{tokens[pos:]}'")
    return _Expr(node=expr)


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class SigmaEngine:
    """Loads rules and evaluates them against telemetry events."""

    def __init__(self, rules: list[SigmaRule] | None = None) -> None:
        self.rules: list[SigmaRule] = rules or []
        self._expressions: dict[str, _Expr] = {}

    # -- loading -----------------------------------------------------------

    @classmethod
    def from_yaml_file(cls, path: Path | str) -> SigmaRule:
        p = Path(path)
        try:
            raw = yaml.safe_load(p.read_text(encoding="utf-8"))
        except yaml.YAMLError as exc:
            raise SigmaRuleLoadError(f"invalid YAML in {p.name}: {exc}") from exc
        if not isinstance(raw, dict):
            raise SigmaRuleLoadError(f"{p.name} does not contain a mapping")
        return cls._rule_from_mapping(raw)

    @classmethod
    def _rule_from_mapping(cls, raw: dict[str, Any]) -> SigmaRule:
        detection = raw.get("detection", {}) or {}
        selections: dict[str, dict[str, Any]] = {}
        order: list[str] = []
        for key, value in detection.items():
            if key in {"condition", "timeframe"}:
                continue
            if isinstance(value, dict):
                selections[key] = dict(value)
            else:
                selections[key] = {"keywords": value}
            order.append(key)
        condition_str = str(detection.get("condition", ""))
        status_raw = str(raw.get("status", "stable"))
        if status_raw not in {s.value for s in SigmaRuleStatus}:
            status_raw = "stable"
        rule = SigmaRule(
            title=str(raw.get("title", "Untitled")),
            id_or_name=str(raw.get("id", "") or raw.get("name", "") or "untitled"),
            status=SigmaRuleStatus(status_raw),
            description=str(raw.get("description", "")),
            references=[str(r) for r in raw.get("references", []) if r],
            author=str(raw.get("author", "")),
            tags=[str(t) for t in raw.get("tags", []) if t],
            logsource=dict(raw.get("logsource", {}) or {}),
            detection=SigmaRuleDetection(
                selections=selections,
                condition=condition_str,
            ),
            level=str(raw.get("level", "informational")),
            fields=[str(f) for f in raw.get("fields", []) if f],
            falsepositives=[str(f) for f in raw.get("falsepositives", []) if f],
        )
        return rule

    def load_directory(self, path: Path | str) -> list[SigmaRule]:
        """Load every ``*.yaml`` rule from a directory in sorted order."""
        source = Path(path)
        loaded: list[SigmaRule] = []
        for file in sorted(source.glob("*.yaml")):
            rule = self.from_yaml_file(file)
            self.rules.append(rule)
            loaded.append(rule)
        return loaded

    # -- evaluation --------------------------------------------------------

    def evaluate(self, rule: SigmaRule, event: TelemetryEvent) -> DetectionEvent:
        """Run one rule against one event, returning a match result."""
        selection_results: dict[str, bool] = {}
        matched_names: list[str] = []
        event_map = event.flat_dict
        for name, selection in rule.detection.selections.items():
            ok = match_selection(selection, event_map)
            selection_results[name] = ok
            if ok:
                matched_names.append(name)
        expr = self._get_expr(rule)
        order = list(rule.detection.selections.keys())
        matched = expr.eval(selection_results, order)
        return DetectionEvent(
            rule_id=rule.name,
            rule_title=rule.title,
            matched=matched,
            event_id=event.event_id,
            confidence=1.0 if matched else 0.0,
            matched_selections=matched_names,
        )

    def detect(self, event: TelemetryEvent) -> list[DetectionEvent]:
        return [self.evaluate(rule, event) for rule in self.rules]

    def detect_all(self, events: list[TelemetryEvent]) -> list[DetectionEvent]:
        out: list[DetectionEvent] = []
        for event in events:
            out.extend(self.detect(event))
        return out

    def _get_expr(self, rule: SigmaRule) -> _Expr:
        key = rule.name
        if key not in self._expressions:
            self._expressions[key] = compile_condition(rule.detection.condition)
        return self._expressions[key]
