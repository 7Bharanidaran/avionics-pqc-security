# Performance Benchmarking and Experimental Evaluation

> **DISCLAIMER**: This document presents empirical micro-benchmarking and protocol latency measurements collected on simulated software test environments. These figures quantify the computational and transmission overhead introduced by hybrid post-quantum cryptography under local test conditions. They do NOT represent universal performance guarantees for certified aerospace flight hardware (e.g. DO-178C / DO-254 embedded avionics).

---

## 1. Benchmark Objective

The objective of this benchmarking suite is to quantify:
1. **Computational Latency**: Execution time for individual cryptographic primitives (X25519, ML-KEM-1024, Ed25519, SLH-DSA shake_128f, HKDF-SHA256, AES-256-GCM).
2. **Protocol Latency**: End-to-end handshake execution duration (FCC ↔ NAV) and secure telemetry message processing.
3. **Data Overhead**: Transmission sizes for public keys, ciphertexts, digital signatures, and encrypted packet envelopes.
4. **Hybrid vs Classical Overhead**: Comparative analysis between a traditional classical baseline (X25519 + Ed25519 + AES) and the hybrid post-quantum protocol.

---

## 2. Methodology & Statistical Rigor

### 2.1 Monotonic High-Resolution Timing
* Benchmarks use Python's highest-resolution monotonic clock: `time.perf_counter_ns()`.
* Wall-clock timers (`time.time()`) are explicitly excluded from timing calculations.

### 2.2 Warm-up & Iterations
* **Warm-up**: Prior to recorded measurements, each operation executes unrecorded warm-up iterations (2 to 5 iterations) to prime CPU caches, Python bytecode dispatch, and dynamic library linking.
* **Configurable Iterations**:
  * Fast primitives (X25519, ML-KEM, Ed25519, HKDF, AES-GCM): 50 iterations.
  * Heavy primitives (SLH-DSA signing, full hybrid handshake): 15 iterations.

### 2.3 Statistical Metrics
For every benchmarked operation, the distribution of raw nanosecond timings is analyzed to produce:
* **Minimum** ($\text{Min}$)
* **Maximum** ($\text{Max}$)
* **Mean** ($\mu$)
* **Median** ($\text{P50}$)
* **Standard Deviation** ($\sigma$)
* **95th Percentile** ($\text{P95}$)

---

## 3. Cryptographic Primitives Benchmark

| Operation | Parameter Set | Median ($\mu\text{s}$) | P95 ($\mu\text{s}$) | Category |
| :--- | :--- | :--- | :--- | :--- |
| **X25519 Key Generation** | Curve25519 | ~54 $\mu\text{s}$ | ~56 $\mu\text{s}$ | Classical Key Exchange |
| **X25519 Shared Secret** | Curve25519 | ~97 $\mu\text{s}$ | ~106 $\mu\text{s}$ | Classical Key Exchange |
| **ML-KEM-1024 KeyGen** | FIPS 203 (NIST Level 5) | ~482 $\mu\text{s}$ | ~666 $\mu\text{s}$ | Post-Quantum KEM |
| **ML-KEM-1024 Encapsulation** | FIPS 203 (NIST Level 5) | ~137 $\mu\text{s}$ | ~160 $\mu\text{s}$ | Post-Quantum KEM |
| **ML-KEM-1024 Decapsulation** | FIPS 203 (NIST Level 5) | ~397 $\mu\text{s}$ | ~675 $\mu\text{s}$ | Post-Quantum KEM |
| **Ed25519 Signing** | RFC 8032 / SHA-512 | ~99 $\mu\text{s}$ | ~159 $\mu\text{s}$ | Classical Signature |
| **Ed25519 Verification** | RFC 8032 / SHA-512 | ~147 $\mu\text{s}$ | ~230 $\mu\text{s}$ | Classical Signature |
| **SLH-DSA Signing** | FIPS 205 (`shake_128f`) | ~1,068 $\text{ms}$ | ~5,097 $\text{ms}$ | Post-Quantum Signature |
| **SLH-DSA Verification** | FIPS 205 (`shake_128f`) | ~71 $\text{ms}$ | ~135 $\text{ms}$ | Post-Quantum Signature |
| **HKDF-SHA256 Derivation** | RFC 5869 | ~38 $\mu\text{s}$ | ~57 $\mu\text{s}$ | Key Derivation |

---

## 4. AES-256-GCM Symmetric Encryption Across Payload Sizes

| Payload Size | Encryption (Median) | Decryption (Median) | Tag Size | Nonce Size |
| :--- | :--- | :--- | :--- | :--- |
| **64 Bytes** | ~24.5 $\mu\text{s}$ | ~24.0 $\mu\text{s}$ | 16 Bytes | 12 Bytes |
| **256 Bytes** | ~26.5 $\mu\text{s}$ | ~23.6 $\mu\text{s}$ | 16 Bytes | 12 Bytes |
| **1024 Bytes** | ~24.4 $\mu\text{s}$ | ~24.0 $\mu\text{s}$ | 16 Bytes | 12 Bytes |
| **4096 Bytes** | ~30.5 $\mu\text{s}$ | ~31.4 $\mu\text{s}$ | 16 Bytes | 12 Bytes |

---

## 5. End-to-End Hybrid Handshake Benchmark

* **Scope**: Complete execution of `HybridHandshake` (FCC ↔ NAV):
  * Ephemeral X25519 + ML-KEM-1024 generation & exchange
  * ML-KEM encapsulation & decapsulation
  * HKDF-SHA256 session key derivation
  * Mutual dual authentication (Ed25519 sign/verify + SLH-DSA sign/verify on both endpoints)
  * Session establishment and registration
* **Handshake Median Latency**: **~2,318 ms (~2.32 s)**
* **Handshake P95 Latency**: **~2,760 ms (~2.76 s)**
* **Dominant Latency Factor**: Pure Python stateless hash-based signature generation (SLH-DSA FIPS 205), which requires constructing hypertree hash chains.

---

## 6. Key and Transmission Size Overhead

| Item | Algorithm | Size (Bytes) | Description |
| :--- | :--- | :--- | :--- |
| **Classical Public Key** | X25519 | 32 B | Curve25519 point |
| **Classical Private Key** | X25519 | 32 B | Scalar |
| **PQC Public Key** | ML-KEM-1024 | 1,568 B | FIPS 203 polynomial matrix |
| **PQC Private Seed** | ML-KEM-1024 | 64 B | Seed for key reconstruction |
| **PQC Ciphertext** | ML-KEM-1024 | 1,568 B | Encapsulated shared secret |
| **Classical Signature** | Ed25519 | 64 B | Detached signature |
| **PQC Signature** | SLH-DSA (`shake_128f`) | 17,088 B | Stateless hash hypertree signature |
| **AEAD Nonce** | AES-GCM | 12 B | 96-bit initialization vector |
| **AEAD Auth Tag** | AES-GCM | 16 B | 128-bit MAC |

---

## 7. Classical Baseline vs. Hybrid PQC Comparison

| Dimension | Classical Baseline | Hybrid PQC Protocol | Overhead Factor |
| :--- | :--- | :--- | :--- |
| **Key Exchange Scheme** | X25519 | X25519 + ML-KEM-1024 | Hybrid Defense-in-Depth |
| **Authentication Scheme** | Ed25519 | Ed25519 + SLH-DSA (`shake_128f`) | Hybrid Defense-in-Depth |
| **Handshake Data Transmitted** | 128 Bytes | 37,440 Bytes | **~292.5x** |
| **Handshake Latency (Median)** | ~0.45 ms | ~2,318 ms | **~5,150x** (Software/Python) |

> [!NOTE]
> In hardware-accelerated C/Rust implementations (e.g. AVX2/AES-NI/SHA extensions), SLH-DSA signature generation executes in 5–15 ms. The software simulation in Python highlights the critical need for hardware cryptographic co-processors on avionics buses when deploying stateless hash-based signatures.

---

## 8. Memory Footprint

* **Cryptographic Keypairs**: < 200 KB total in-memory object allocation.
* **Handshake Peak Heap Memory**: ~1.2 MB during hypertree hash node allocation.
* **Active Secure Session Object**: < 500 bytes per established peer channel.

---

## 9. Reproducibility Instructions

To execute the benchmark suite and generate updated JSON and CSV telemetry:

```bash
python backend/benchmark/run_benchmarks.py
```

Generated artifact locations:
* **JSON**: `data/benchmarks/latest.json` and `data/benchmarks/benchmark_YYYYMMDD_HHMMSS.json`
* **CSV**: `data/benchmarks/latest.csv`
