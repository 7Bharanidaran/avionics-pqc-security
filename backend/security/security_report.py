"""Security Validation Report Generator for Avionics PQC Security Lab.

Aggregates the execution results of baseline communication and attack simulations,
evaluating protocol robustness against the tested threat scenarios.
"""

from __future__ import annotations

import time
from typing import Any

from backend.security.attack_simulation import (
    AttackResult,
    AttackStatus,
    run_all_attack_simulations,
)


class SecurityReport:
    """Encapsulates the aggregated findings of the security validation suite."""

    def __init__(self, results: list[AttackResult]):
        self.results = results
        self.timestamp = time.time()

        # Separate baseline from attacks
        self.baseline_result = next((r for r in results if r.attack_id == "ATK-00"), None)
        self.attack_results = [r for r in results if r.attack_id != "ATK-00"]

    @property
    def total_attacks(self) -> int:
        """Total number of attack scenarios evaluated."""
        return len(self.attack_results)

    @property
    def attacks_detected(self) -> int:
        """Number of attacks successfully detected and mitigated."""
        return sum(1 for r in self.attack_results if r.detected)

    @property
    def attacks_not_detected(self) -> int:
        """Number of attacks that bypassed security checks."""
        return sum(1 for r in self.attack_results if not r.detected and r.status != AttackStatus.ERROR)

    @property
    def errors(self) -> int:
        """Number of simulations encountering unexpected runtime errors."""
        return sum(1 for r in self.attack_results if r.status == AttackStatus.ERROR)

    @property
    def baseline_passed(self) -> bool:
        """Check if legitimate baseline communication passed."""
        return self.baseline_result is not None and self.baseline_result.status == AttackStatus.DETECTED

    @property
    def overall_status(self) -> str:
        """Return overall security validation status."""
        if not self.baseline_passed:
            return "BASELINE_FAILED"
        if self.attacks_detected == self.total_attacks:
            return "PASS"
        if self.attacks_detected > 0:
            return "PARTIAL"
        return "FAIL"

    def to_dict(self) -> dict[str, Any]:
        """Serialize complete report to dictionary."""
        return {
            "timestamp": self.timestamp,
            "overall_status": self.overall_status,
            "baseline_passed": self.baseline_passed,
            "total_attacks": self.total_attacks,
            "attacks_detected": self.attacks_detected,
            "attacks_not_detected": self.attacks_not_detected,
            "errors": self.errors,
            "results": [r.to_dict() for r in self.results],
        }

    def generate_summary_text(self) -> str:
        """Generate human-readable CLI summary text."""
        lines = [
            "==================================================",
            "SECURITY VALIDATION REPORT",
            "==================================================",
            f"Baseline: {'PASS' if self.baseline_passed else 'FAIL'}",
            "",
        ]

        for r in self.attack_results:
            status_text = r.status.value
            lines.append(f"{r.attack_name}:")
            lines.append(f"{status_text}")
            lines.append("")

        lines.extend([
            "==================================================",
            "SUMMARY",
            "==================================================",
            f"Attacks detected    : {self.attacks_detected} / {self.total_attacks}",
            f"Attacks not detected: {self.attacks_not_detected} / {self.total_attacks}",
            f"Security validation : {self.overall_status}",
            "==================================================",
        ])

        return "\n".join(lines)


def generate_security_report() -> SecurityReport:
    """Execute all simulations and generate a comprehensive SecurityReport."""
    results = run_all_attack_simulations()
    return SecurityReport(results)
