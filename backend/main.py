"""Avionics PQC Security Lab - Phase 5 Security Validation Demonstrator.

Executes real security attack simulations against the hybrid post-quantum protocol:
- Baseline Legitimate Transmission
- Ciphertext Bit-Flip Tampering
- GCM Authentication Tag Tampering
- AAD Metadata Tampering
- Ed25519 Signature Forgery
- SLH-DSA Signature Forgery
- Handshake Transcript Tampering
- Wrong Session Injection
- Wrong Receiver Spoofing
- Replay Protection
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure UTF-8 console output encoding on Windows
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.security import (
    AttackStatus,
    generate_security_report,
)


def run_phase5_demonstrator() -> None:
    """Execute the Phase 5 Security Attack Simulation and Validation."""
    print("==================================================")
    print("AVIONICS PQC SECURITY LAB")
    print("PHASE 5")
    print("SECURITY VALIDATION")
    print("==================================================")
    print()

    # Generate real report by running all simulations
    report = generate_security_report()

    print("BASELINE")
    print("--------------------------------------------")
    print()
    print("FCC → NAV")
    print("Message:")
    print("ALTITUDE = 32000 FT")
    print()
    print("Secure transmission:")
    print("PASS ✓" if report.baseline_passed else "FAIL ✗")
    print()
    print("Message recovered:")
    print("ALTITUDE = 32000 FT")
    print()
    print("==================================================")
    print("ATTACK SIMULATION")
    print("==================================================")
    print()

    idx = 1
    for attack in report.attack_results:
        symbol = "✓" if attack.detected else "✗"
        print(f"[{idx:02d}] {attack.attack_name}")
        print(f"Result: {attack.status.value} {symbol}")
        print()
        idx += 1

    print("==================================================")
    print("SECURITY VALIDATION SUMMARY")
    print("==================================================")
    print()
    print("Baseline:")
    print("PASS" if report.baseline_passed else "FAIL")
    print()
    print("Attacks detected:")
    print(f"{report.attacks_detected} / {report.total_attacks}")
    print()
    print("Attacks not detected:")
    print(f"{report.attacks_not_detected} / {report.total_attacks}")
    print()
    print("Security validation:")
    print(f"{report.overall_status}")
    print()
    print("==================================================")


if __name__ == "__main__":
    run_phase5_demonstrator()
