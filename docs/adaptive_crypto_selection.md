# Safety-Constrained Adaptive Hybrid-PQC Profile Selection

## Problem and motivation

This simulation/research prototype implements an avionics-oriented safety-constrained adaptive hybrid-PQC profile selection mechanism that combines message criticality, simulated threat state, measured cryptographic performance, and latency constraints. It selects an approved operational profile before a secure session is established. It does not alter cryptographic primitives or claim aircraft certification.

## Architecture

`Policy request -> hard safety filter -> Phase 6 benchmark evaluation -> transparent scoring -> policy decision -> existing HybridHandshake / SecureSession`.

The policy layer is separate from `backend/crypto` and `backend/protocol`. Both executable profiles use the existing X25519, ML-KEM-1024, HKDF-SHA256, Ed25519, SLH-DSA-SHAKE_128F, and AES-256-GCM implementation. A policy selection is therefore operational metadata, not a claim of dynamic primitive switching.

## Criticality and threat model

Criticality is `ROUTINE`, `IMPORTANT`, `CRITICAL`, or `SAFETY_CRITICAL`. Their minimum assurance levels are respectively STANDARD, HIGH, HIGH, and MAXIMUM. The controlled simulation threat state is `NORMAL`, `ELEVATED`, `HIGH`, or `CRITICAL`, requiring STANDARD, STANDARD, HIGH, and MAXIMUM assurance. It is not real-world threat intelligence.

## Approved profiles and constraints

`STANDARD_HYBRID` permits routine traffic through elevated threat. `HIGH_ASSURANCE_HYBRID` permits all criticality and threat levels. Both are approved and retain the same existing hybrid cryptographic primitives; their distinction is assurance policy and operational eligibility. A non-executable classical-only sentinel is retained only for rule testing and can never be selected.

Hard filtering rejects profiles that are unapproved, below required assurance, unable to support the current threat, or ineligible for the message criticality. This enforces these safety rules:

- Safety-critical traffic requires maximum assurance.
- Critical traffic has no classical-only fallback.
- High and critical threat cannot reduce assurance.
- Only approved profiles can be selected.
- Security requirements take priority over latency.
- If latency cannot meet a mandatory profile, the outcome is `CONSTRAINT_CONFLICT`; the engine never downgrades cryptography to satisfy latency.

## Scoring and benchmark integration

After hard safety filtering, the deterministic score is:

`0.45 * security suitability + 0.25 * threat suitability + 0.20 * latency suitability + 0.10 * resource suitability`.

Security and threat suitability favor the profile that meets the requirement without unnecessary operational surplus. Latency suitability is derived from `data/benchmarks/latest.json`, specifically the Phase 6 `Total Hybrid Handshake Latency` median. No benchmark measurement is hardcoded. A missing or invalid benchmark dataset returns a safe no-feasible-profile result.

## API and frontend

- `POST /api/policy/evaluate` evaluates a request.
- `GET /api/policy/profiles` returns approved profile metadata and the measured handshake latency.
- `GET /api/policy/rules` returns requirement mappings, weights, and safety rules.
- `GET /api/policy/metrics` returns real in-memory current-session evaluation counters.

The Adaptive Policy page uses these endpoints for live input evaluation, constraint checks, profile comparison, and controlled experiments. It has no synthetic measurements, telemetry, or cryptographic calculations.

## Controlled experiments and research comparison

The page can run five fixed requests: routine/normal/1000 ms, important/elevated/500 ms, critical/high/1000 ms, safety-critical/critical/500 ms, and safety-critical/critical/100 ms. Results are generated at execution time by the API and are not pre-populated.

The research comparison is between a baseline fixed hybrid configuration and adaptive safety-constrained profile selection. Measurements to record are policy decision time, selected profile, Phase 6 cryptographic latency, constraint conflicts, blocked downgrades, and satisfaction of the mandatory security requirement. This repository does not claim results until the experiments are executed against a particular benchmark dataset.

## Limitations

The model is deterministic and intentionally small. It uses a local software benchmark rather than representative certified avionics hardware, stores current-session metrics only in memory, and currently uses the same implemented hybrid primitive suite for all executable profiles. It is a research prototype, not an aviation-certified security system.
