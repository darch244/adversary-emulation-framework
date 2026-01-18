"""Detection engineering: synthetic telemetry, Sigma engine, and gap reporting."""

from detection.matrix_reporter import CoverageGap, DetectionMatrix, MatrixReporter
from detection.sigma_engine import (
    ConditionParseError,
    SigmaEngine,
    SigmaMatch,
    SigmaRuleLoadError,
)
from detection.telemetry_logger import SyntheticTelemetryLogger

__all__ = [
    "ConditionParseError",
    "CoverageGap",
    "DetectionMatrix",
    "MatrixReporter",
    "SigmaEngine",
    "SigmaMatch",
    "SigmaRuleLoadError",
    "SyntheticTelemetryLogger",
]
