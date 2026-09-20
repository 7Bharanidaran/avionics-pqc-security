# Avionics Post-Quantum Cryptographic Protocol Specification (Phase 4 & 5)

## 1. Overview

This document specifies the complete hybrid secure communications protocol for the `avionics-pqc-security` platform. The protocol establishes quantum-resistant, mutually authenticated communication sessions across avionics computers (FCC, NAV) and Ground Control Stations (GCS) over untrusted physical datalinks.

---

## 2. Protocol Sequence Diagram

```
Initiator (e.g. FCC)                                Responder (e.g. NAV)
────────────────────                                ─────────────────────
1. Generate Ephemeral Keys:
   - X25519: (init_x_priv, init_x_pub)
   - ML-KEM-1024: (init_ml_seed, init_ml_pub)
   State: INITIAL -> KEY_EXCHANGE

   ─────────────── Handshake Init (PubKeys) ──────────────►
                                                    2. Key Agreement & Encapsulation:
                                                       - Generate X25519: (resp_x_priv, resp_x_pub)
                                                       - Encapsulate ML-KEM: (resp_ml_ss, mlkem_ct)
                                                       - X25519 Derive: resp_x_ss = X25519(resp_x_priv, init_x_pub)
                                                       - Combine IKM: resp_hybrid = resp_x_ss || resp_ml_ss
                                                       - Compute Canonical Transcript
                                                       - HKDF-SHA256 Derive: resp_session_key
                                                       - Sign Transcript Hash:
                                                         * Ed25519 signature
                                                         * SLH-DSA (shake_128f) signature
                                                       State: KEY_DERIVED -> AUTHENTICATING

   ◄────────── Handshake Response (PubKeys + CT + Sigs) ───
3. Decapsulation & Verification:
   - Decapsulate ML-KEM: init_ml_ss = Decap(init_ml_seed, mlkem_ct)
   - X25519 Derive: init_x_ss = X25519(init_x_priv, resp_x_pub)
   - Combine IKM: init_hybrid = init_x_ss || init_ml_ss
   - Compute Canonical Transcript
   - HKDF-SHA256 Derive: init_session_key
   - Verify Responder Signatures:
     * Ed25519 Verify (MUST PASS)
     * SLH-DSA Verify (MUST PASS)
   - Sign Transcript Hash (Ed25519 + SLH-DSA)
   - State: AUTHENTICATING -> AUTHENTICATED -> ESTABLISHED

   ─────────────── Handshake Finalize (Sigs) ─────────────►
                                                    4. Finalize Authentication:
                                                       - Verify Initiator Signatures:
                                                         * Ed25519 Verify (MUST PASS)
                                                         * SLH-DSA Verify (MUST PASS)
                                                       - State: AUTHENTICATED -> ESTABLISHED

═════════════════════════════════════════════════════════════════════════════
                 SECURE SESSION ESTABLISHED (AES-256-GCM)
═════════════════════════════════════════════════════════════════════════════
5. Encrypt Telemetry:
   - Generate random 12-byte Nonce
   - Bind Canonical AAD metadata
   - AES-256-GCM Encrypt(msg, aad, nonce)

   ────────── EncryptedPacketEnvelope (Ciphertext + Nonce + AAD) ───────► (Untrusted Channel)
                                                    6. Decrypt & Verify Telemetry:
                                                       - Check Nonce Freshness (Replay Filter)
                                                       - AES-256-GCM Decrypt(ct, aad, nonce)
                                                       - Verify AAD binding
                                                       - Reconstruct AvionicsMessage
```

---

## 3. Protocol Steps & State Machine

### 3.1 Handshake Initialization & Key Exchange
* **Initiator State**: Transitions `INITIAL` -> `KEY_EXCHANGE`.
* Generates ephemeral X25519 keypair: `init_x_priv`, `init_x_pub` (32 bytes each).
* Generates ephemeral ML-KEM-1024 keypair: `init_ml_seed` (64 bytes), `init_ml_pub` (1568 bytes).
* Sends public keys to Responder.

### 3.2 Responder Encapsulation & Shared Secret Computation
* Responder generates ephemeral X25519 keypair: `resp_x_priv`, `resp_x_pub`.
* Encapsulates a random 32-byte shared secret against `init_ml_pub` generating `resp_ml_ss` (32 bytes) and `mlkem_ciphertext` (1568 bytes).
* Performs Diffie-Hellman exchange: `resp_x_ss = X25519(resp_x_priv, init_x_pub)` (32 bytes).
* Concatenates hybrid key material: `resp_hybrid_ikm = resp_x_ss || resp_ml_ss` (64 bytes).

### 3.3 Initiator Decapsulation & Shared Secret Computation
* Initiator decapsulates `mlkem_ciphertext` using `init_ml_seed` to recover `init_ml_ss` (32 bytes).
* Performs Diffie-Hellman exchange: `init_x_ss = X25519(init_x_priv, resp_x_pub)` (32 bytes).
* Concatenates hybrid key material: `init_hybrid_ikm = init_x_ss || init_ml_ss` (64 bytes).
* Both sides have derived identical 64-byte `hybrid_ikm`.

### 3.4 Canonical Transcript Construction
Both endpoints independently build the canonical transcript JSON:
```json
{
  "algorithms": {
    "aead": "AES-256-GCM",
    "auth_classical": "Ed25519",
    "auth_pqc": "SLH-DSA-SHAKE_128F",
    "kdf": "HKDF-SHA256",
    "kex_classical": "X25519",
    "kex_pqc": "ML-KEM-1024"
  },
  "initiator_id": "AIRCRAFT-001-FCC",
  "initiator_mlkem_pub_hex": "<1568 bytes hex>",
  "initiator_x25519_pub_hex": "<32 bytes hex>",
  "mlkem_ciphertext_hex": "<1568 bytes hex>",
  "protocol_version": "AVIONICS-PQC-V1",
  "responder_id": "AIRCRAFT-001-NAV",
  "responder_x25519_pub_hex": "<32 bytes hex>"
}
```
* **Transcript Hash**: `transcript_hash = SHA-256(transcript_bytes)`.
* **Session ID**: `session_id = SHA-256("SESSION_ID:" + transcript_bytes).hexdigest()`.

### 3.5 Session Key Derivation (HKDF-SHA256)
* **Salt**: `SHA-256("AVIONICS_PQC_SALT:" + transcript_bytes)`
* **Info**: `b"AVIONICS_HYBRID_PQC_SESSION_KEY_V1"`
* **Output**: Exactly 32 bytes (256 bits) for AES-256-GCM.
* Transitions state to `KEY_DERIVED`.

### 3.6 Dual Authentication (Ed25519 + SLH-DSA)
* State transitions `KEY_DERIVED` -> `AUTHENTICATING`.
* Each entity signs `transcript_hash` with its registered long-term keys:
  * `ed_sig = Ed25519_Sign(ed_priv, transcript_hash)` (64 bytes)
  * `slh_sig = SLH_DSA_Sign(slh_sec, transcript_hash)` (17,088 bytes)
* Each entity verifies the peer's signatures:
  * `Ed25519_Verify(peer_ed_pub, transcript_hash, ed_sig)` MUST BE `True`.
  * `SLH_DSA_Verify(peer_slh_pub, transcript_hash, slh_sig)` MUST BE `True`.
* **Security Rule**: Both signatures MUST verify successfully. If either fails, the session transitions to `FAILED`.
* On success, state transitions `AUTHENTICATED` -> `ESTABLISHED`.

---

## 4. Secure Telemetry Messaging (AES-256-GCM)

### 4.1 Additional Authenticated Data (AAD)
Every message binds metadata into AES-GCM AAD to prevent cross-session replay, entity impersonation, and packet substitution:
```json
{
  "message_id": "8f3b2d10-...",
  "message_type": "ALTITUDE",
  "protocol_version": "AVIONICS-PQC-V1",
  "receiver_id": "AIRCRAFT-001-NAV",
  "sender_id": "AIRCRAFT-001-FCC",
  "session_id": "4e7a89bc..."
}
```

### 4.2 Nonce Strategy & Replay Filter
* Every packet generates a cryptographically secure 12-byte (96-bit) random nonce via OS CSPRNG (`os.urandom(12)`).
* The receiving `SecureSession` maintains an in-memory replay set of processed nonces (`_seen_nonces`).
* Re-transmitting any duplicate nonce triggers a `ReplayAttackError` and aborts decryption.

---

## 5. Security Validation

The protocol's threat resistance was experimentally validated across 10 controlled scenarios:

1. **Ciphertext Tampering**: Bit-flipping encrypted payload causes AES-GCM tag verification failure (`AuthenticationTagError`).
2. **GCM Tag Tampering**: Altering 16-byte authentication tag causes tag verification failure (`AuthenticationTagError`).
3. **AAD Metadata Tampering**: Modifying unencrypted metadata (sender/receiver/session ID) causes AAD mismatch in MAC (`AuthenticationTagError`).
4. **Ed25519 Signature Forgery**: Substituting unauthorized classical key aborts handshake (`HandshakeAuthenticationError`).
5. **SLH-DSA Signature Forgery**: Substituting unauthorized post-quantum key aborts handshake (`HandshakeAuthenticationError`).
6. **Transcript Modification**: Altering handshake parameters triggers signature validation failure on both endpoints.
7. **Wrong Session Confusion**: Delivering ciphertext from Session A to Session B fails decryption due to key isolation and session ID AAD binding.
8. **Wrong Receiver Spoofing**: Delivering message addressed to GCS to NAV causes receiver ID mismatch (`ProtocolError`).
9. **Replay Attack**: Re-submitting an already-processed envelope triggers `ReplayAttackError`.
