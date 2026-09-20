# Security Testing & Threat Validation Report

> **DISCLAIMER**: This document details software-level simulation tests against the in-memory hybrid Post-Quantum Cryptographic protocol. These tests demonstrate resistance to the tested message tampering, forgery, and replay scenarios within the defined threat model, but do NOT prove absolute security against all possible side-channel or physical hardware attack vectors.

---

## 1. Threat Model & Assumptions

The simulated aerospace communication system assumes the following threat environment:

* **Adversary Capabilities**:
  * **Eavesdropping (Passive)**: The adversary can monitor all physical datalinks (VHF, SATCOM, ARINC 429 / AFDX internal buses).
  * **Active Tampering (Man-in-the-Middle)**: The adversary can intercept, modify, delete, or inject arbitrary packets into the untrusted communication channel.
  * **Cryptanalytic Capabilities**:
    * Possesses classical computing power to attempt brute-force or classical algebraic attacks.
    * Possesses future Fault-Tolerant Quantum Computing (CRQC) capabilities capable of executing Shor's algorithm against classical discrete logarithm and elliptic curve cryptography (ECC / X25519 / Ed25519).
* **Security Boundaries & Trusted Computing Base (TCB)**:
  * Airborne computers (FCC, NAV) and ground systems (GCS) maintain secure local storage for their long-term private keys and ephemeral seeds.
  * Side-channel leakage (DPA, electromagnetic emissions, timing attacks) is out of scope for this high-level software simulation model.

---

## 2. Attack Scenarios & Evaluation

| Scenario ID | Attack Vector | Target Mechanism | Expected Behavior | Observed Result | Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **ATK-00** | Legitimate Transmission | End-to-End Pipeline | Message accepted and authenticated | Reconstructed `ALTITUDE = 32000 FT` | **PASS** |
| **ATK-01** | Ciphertext Tampering | AES-256-GCM AEAD | Authentication tag verification fails | `AuthenticationTagError` raised; packet dropped | **DETECTED** |
| **ATK-02** | GCM Tag Tampering | 128-bit MAC Tag | Cryptographic verification fails | `AuthenticationTagError` raised; packet dropped | **DETECTED** |
| **ATK-03** | AAD Metadata Tampering | Associated Data Binding | Metadata mismatch in MAC computation | `AuthenticationTagError` raised; packet dropped | **DETECTED** |
| **ATK-04** | Ed25519 Signature Forgery | Handshake Authentication | Classical signature check fails | `HandshakeAuthenticationError`; session `FAILED` | **DETECTED** |
| **ATK-05** | SLH-DSA Signature Forgery | Post-Quantum Authentication | FIPS 205 signature check fails | `HandshakeAuthenticationError`; session `FAILED` | **DETECTED** |
| **ATK-06** | Transcript Modification | Canonical Handshake Transcript | Hash mismatch in dual signatures | Signatures on tampered hash fail; session `FAILED` | **DETECTED** |
| **ATK-07** | Wrong Session Confusion | Session Key Separation | Decryption fails with wrong key/AAD | `AuthenticationTagError` raised; packet rejected | **DETECTED** |
| **ATK-08** | Wrong Receiver Spoofing | Identity Routing Validation | Receiver ID mismatch | `ProtocolError` raised; packet rejected | **DETECTED** |
| **ATK-09** | Replay Attack | Nonce Freshness & Cache | Nonce reuse detected | `ReplayAttackError` raised; duplicate dropped | **DETECTED** |

---

## 3. Security Invariants Proved by Test Suite

1. **INVARIANT 1 (Authenticity & Integrity)**: A legitimate, unmodified message transmitted over the untrusted channel is always accepted.
2. **INVARIANT 2 (Confidentiality & Integrity)**: Any bit-flip in ciphertext payload causes immediate rejection before reaching application logic.
3. **INVARIANT 3 (Tag Tampering)**: Any alteration to the 128-bit authentication tag is rejected.
4. **INVARIANT 4 (Header Integrity)**: Unencrypted metadata (sender ID, receiver ID, session ID, message ID) bound as AAD cannot be altered in transit without detection.
5. **INVARIANT 5 (Classical Authentication)**: Unauthorized or forged Ed25519 signatures prevent session establishment.
6. **INVARIANT 6 (Quantum Authentication)**: Unauthorized or forged SLH-DSA signatures prevent session establishment.
7. **INVARIANT 7 (Transcript Binding)**: Any parameter injection or modification in the canonical handshake transcript prevents session establishment.
8. **INVARIANT 8 (Session Isolation)**: A packet encrypted under Session A cannot be accepted by a receiver operating under Session B.
9. **INVARIANT 9 (Recipient Validation)**: A packet addressed to a different component is rejected upon arrival.

---

## 4. Known Limitations & Future Work

1. **Sliding Window Replay Filter**: The current replay filter caches seen nonces in-memory for the lifetime of the session. In long-running airborne missions with millions of packets, a bounded sliding window counter or epoch-based nonce filter should be implemented.
2. **Side-Channel Hardening**: Constant-time execution guarantees depend on the underlying C/Rust cryptographic libraries (`cryptography`, OpenSSL, `SLH-DSA`).
3. **Key Revocation & Certificates**: Current simulation uses statically configured long-term public keys. Future iterations should incorporate a post-quantum Public Key Infrastructure (PQ-PKI) with hybrid X.509 certificates and CRL/OCSP validation.
