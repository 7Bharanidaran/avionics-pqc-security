# Avionics Post-Quantum Cryptographic Simulation Architecture

> **DISCLAIMER**: This project is a software-based research and simulation model designed to benchmark and evaluate Post-Quantum Cryptographic (PQC) hybrid algorithms for aerospace communication. It does NOT interface with, control, or operate real avionics hardware or aircraft systems.

---

## 1. System Overview

The system models a secure communication environment for next-generation avionics platforms resilient against both classical and quantum adversaries. The simulation consists of airborne components within a simulated aircraft (`AIRCRAFT-001`) and ground-based command infrastructure (`GROUND-STATION-001`).

```
                              AIRCRAFT-001
                    ┌──────────────────────────────┐
                    │                              │
                    │  [Flight Control Computer]   │
                    │      (AIRCRAFT-001-FCC)      │
                    │              │               │
                    │              │ Internal Bus  │
                    │              ▼               │
                    │   [Navigation Computer]      │
                    │      (AIRCRAFT-001-NAV)      │
                    │                              │
                    └──────────────┬───────────────┘
                                   │
                                   │ Untrusted Datalink
                                   │ (VHF / SATCOM Simulation)
                                   ▼
                       [Ground Control Station]
                         (GROUND-STATION-001)
```

---

## 2. Layered Protocol Architecture & Security Testing Layer

```
[ Flight Control Computer (FCC) ]
             │
             │ AvionicsMessage (ALTITUDE, HEADING, etc.)
             ▼
[ Secure Protocol Layer (SecureSession) ]
   - Manages Handshake State Machine (INITIAL -> ESTABLISHED)
   - Canonical Handshake Transcript Construction
   - Dual Authentication (Ed25519 + SLH-DSA)
   - Builds Canonical AAD Metadata & Replay Filter
             │
             │ Handshake Messages / Telemetry Plaintext + AAD
             ▼
[ Cryptographic Foundation Layer ]
   - Hybrid KEX: X25519 + ML-KEM-1024
   - Key Derivation: HKDF-SHA256 (256-bit Session Key)
   - Signatures: Ed25519 (RFC 8032) + SLH-DSA (FIPS 205)
   - Authenticated Encryption: AES-256-GCM (96-bit Nonce, 128-bit Tag)
             │
             │ EncryptedPacketEnvelope (Opaque Ciphertext + Nonce + AAD)
═════════════╪═══════════════════════════════════════════════════════════════════
   UNTRUSTED TRANSPORT & ADVERSARIAL INJECTION BOUNDARY
═════════════╪═══════════════════════════════════════════════════════════════════
             ▼
[ Security Attack Simulation Framework (backend/security) ]
   - Ciphertext Bit-Flip Injector
   - Authentication Tag Corrupter
   - AAD Metadata Manipulator
   - Signature Forger (Ed25519 & SLH-DSA)
   - Transcript Tamperer
   - Replay Packet Injector
             │
             ▼
[ Untrusted Communication Channel (SimulatedChannel) ]
   - Transports EncryptedPacketEnvelope across simulated bus / datalink
   - CANNOT inspect plaintext or decrypt payload
   - Has ZERO access to session keys or private keys
═════════════╪═══════════════════════════════════════════════════════════════════
   RECIPIENT SECURE ENCLAVE
═════════════╪═══════════════════════════════════════════════════════════════════
             ▼
[ Cryptographic Foundation Layer (Receiver) ]
   - AES-256-GCM Tag Verification & Decryption
   - Ed25519 + SLH-DSA Signature Verification
             │
             │ Validated Plaintext + AAD
             ▼
[ Secure Protocol Layer (Receiver) ]
   - Enforces Nonce Freshness (Replay Filter)
   - Enforces AAD & Session ID Integrity Check
   - Reconstructs AvionicsMessage
             │
             ▼
[ Navigation Computer (NAV) / Ground Control Station (GCS) ]
```

---

## 3. Simulated Entities

### 3.1 Flight Control Computer (FCC)
* **Identifier**: `AIRCRAFT-001-FCC`
* **Type**: `FLIGHT_CONTROL_COMPUTER`
* **Aircraft Association**: `AIRCRAFT-001`
* **Role**: Simulates airborne flight guidance and control state generation. Creates telemetry and command messages (`ALTITUDE`, `HEADING`, `FLIGHT_MODE`, `AIRCRAFT_STATUS`), manages hybrid cryptographic identities, initiates secure session handshakes, and encrypts outgoing datalink packets.

### 3.2 Navigation Computer (NAV)
* **Identifier**: `AIRCRAFT-001-NAV`
* **Type**: `NAVIGATION_COMPUTER`
* **Aircraft Association**: `AIRCRAFT-001`
* **Role**: Simulates aircraft sensor fusion and positioning state (`NAVIGATION_UPDATE`). Participates in secure key exchanges, verifies incoming cryptographically protected control messages, and enforces strict authentication checks.

### 3.3 Ground Control Station (GCS)
* **Identifier**: `GROUND-STATION-001`
* **Type**: `GROUND_CONTROL_STATION`
* **Aircraft Association**: None (Ground Infrastructure)
* **Role**: Simulates ground operations, air traffic management, and dispatch command injection. Conducts mutual authentication and hybrid key exchanges with airborne entities.

---

## 4. Security Attack Validation Layer

The security validation subsystem (`backend/security`) provides automated testing for:
* **Ciphertext Tampering**: Verifies AEAD GCM integrity.
* **Authentication Tag Tampering**: Verifies MAC check.
* **AAD Metadata Manipulation**: Verifies unencrypted header binding.
* **Dual Signature Forgeries**: Verifies classical and post-quantum digital signature enforcement.
* **Transcript Tampering**: Verifies canonical transcript binding.
* **Cross-Session Injection**: Verifies session key isolation.
* **Receiver Spoofing**: Verifies component ID binding.
* **Replay Attacks**: Verifies nonce cache freshness.
