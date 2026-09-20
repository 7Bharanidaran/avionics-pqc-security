"""Approved operational profiles; all executable profiles use the existing hybrid protocol."""
from .models import AssuranceLevel, Criticality, CryptoProfile, ThreatLevel


STANDARD_HYBRID = CryptoProfile(
    profile_id="STANDARD_HYBRID", assurance_level=AssuranceLevel.STANDARD,
    key_agreement="X25519", kem="ML-KEM-1024", authentication="Ed25519 + SLH-DSA-SHAKE_128F",
    aead="AES-256-GCM", allowed_criticality=(Criticality.ROUTINE,),
    maximum_threat=ThreatLevel.ELEVATED, resource_score=80.0,
)
HIGH_ASSURANCE_HYBRID = CryptoProfile(
    profile_id="HIGH_ASSURANCE_HYBRID", assurance_level=AssuranceLevel.MAXIMUM,
    key_agreement="X25519", kem="ML-KEM-1024", authentication="Ed25519 + SLH-DSA-SHAKE_128F",
    aead="AES-256-GCM", allowed_criticality=tuple(Criticality),
    maximum_threat=ThreatLevel.CRITICAL, resource_score=60.0,
)
# A policy sentinel, deliberately excluded from execution and selection. It does not claim to be implemented.
UNAPPROVED_CLASSICAL_ONLY = CryptoProfile(
    profile_id="UNAPPROVED_CLASSICAL_ONLY", assurance_level=AssuranceLevel.STANDARD,
    key_agreement="Not executable", kem="Not executable", authentication="Not executable", aead="Not executable",
    allowed_criticality=(Criticality.ROUTINE,), maximum_threat=ThreatLevel.NORMAL, approved=False,
)

APPROVED_PROFILES = (STANDARD_HYBRID, HIGH_ASSURANCE_HYBRID)
ALL_PROFILES = (*APPROVED_PROFILES, UNAPPROVED_CLASSICAL_ONLY)
