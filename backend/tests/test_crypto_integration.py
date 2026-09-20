"""Cryptographic integration test demonstrating the full hybrid PQC pipeline.

Pipeline flow:
    Party A (FCC)                           Party B (Ground Station)
    -------------                           ------------------------
    1. Ephemeral X25519 KeyGen              1. Ephemeral X25519 KeyGen
    2. Ephemeral ML-KEM KeyGen              2. (Receives ML-KEM PubKey)
    3. Long-term Ed25519 + SLH-DSA Sign     3. Verify Ed25519 + SLH-DSA signatures
                                            4. ML-KEM Encapsulate (ss_ml, ct)
    5. ML-KEM Decapsulate (ss_ml)           5. Derive X25519 SS (ss_x)
    6. Derive X25519 SS (ss_x)
    7. Hybrid Key Material = ss_x || ss_ml  7. Hybrid Key Material = ss_x || ss_ml
    8. HKDF(ikm=hybrid) -> AES-256 Key      8. HKDF(ikm=hybrid) -> AES-256 Key
    9. AES-256-GCM Encrypt                  9. AES-256-GCM Decrypt
       "ALTITUDE=32000FT"                      "ALTITUDE=32000FT"
"""

import pytest
from backend.crypto import (
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    aes_gcm_generate_nonce,
    ed25519_generate_keypair,
    ed25519_sign,
    ed25519_verify,
    hkdf_derive,
    mlkem_decapsulate,
    mlkem_encapsulate,
    mlkem_generate_keypair,
    slhdsa_generate_keypair,
    slhdsa_sign,
    slhdsa_verify,
    x25519_derive_shared_secret,
    x25519_generate_keypair,
)


def test_full_hybrid_pqc_pipeline_integration():
    """Verify the end-to-end hybrid cryptographic flow with exact test message."""
    test_message = b"ALTITUDE=32000FT"

    # -------------------------------------------------------------
    # Step 1: Long-term Hybrid Authentication Keys (Ed25519 + SLH-DSA)
    # -------------------------------------------------------------
    # Party A (e.g. Flight Control Computer - FCC)
    fcc_ed_priv, fcc_ed_pub = ed25519_generate_keypair()
    fcc_slh_sec, fcc_slh_pub = slhdsa_generate_keypair("shake_128f")

    # Party B (e.g. Ground Station - GCS)
    gcs_ed_priv, gcs_ed_pub = ed25519_generate_keypair()
    gcs_slh_sec, gcs_slh_pub = slhdsa_generate_keypair("shake_128f")

    # -------------------------------------------------------------
    # Step 2: Ephemeral Key Exchange Material (X25519 + ML-KEM-1024)
    # -------------------------------------------------------------
    # FCC generates ephemeral X25519 and ML-KEM keypairs
    fcc_x_priv, fcc_x_pub = x25519_generate_keypair()
    fcc_ml_priv_seed, fcc_ml_pub = mlkem_generate_keypair("ML-KEM-1024")

    # GCS generates ephemeral X25519 keypair
    gcs_x_priv, gcs_x_pub = x25519_generate_keypair()

    # FCC signs its ephemeral public keys using both classical (Ed25519) and post-quantum (SLH-DSA)
    fcc_handshake_bundle = fcc_x_pub + fcc_ml_pub
    fcc_ed_sig = ed25519_sign(fcc_ed_priv, fcc_handshake_bundle)
    fcc_slh_sig = slhdsa_sign(fcc_slh_sec, fcc_handshake_bundle, "shake_128f")

    # -------------------------------------------------------------
    # Step 3: GCS Verifies FCC Signatures
    # -------------------------------------------------------------
    assert ed25519_verify(fcc_ed_pub, fcc_handshake_bundle, fcc_ed_sig) is True
    assert slhdsa_verify(fcc_slh_pub, fcc_handshake_bundle, fcc_slh_sig, "shake_128f") is True

    # -------------------------------------------------------------
    # Step 4: GCS Performs Key Agreement (X25519 + ML-KEM Encapsulation)
    # -------------------------------------------------------------
    # GCS encapsulates against FCC's ML-KEM public key
    gcs_ml_shared_secret, mlkem_ciphertext = mlkem_encapsulate(fcc_ml_pub, "ML-KEM-1024")

    # GCS computes X25519 shared secret
    gcs_x_shared_secret = x25519_derive_shared_secret(gcs_x_priv, fcc_x_pub)

    # -------------------------------------------------------------
    # Step 5: FCC Decapsulates and Computes Shared Secrets
    # -------------------------------------------------------------
    # FCC decapsulates ML-KEM ciphertext
    fcc_ml_shared_secret = mlkem_decapsulate(fcc_ml_priv_seed, mlkem_ciphertext, "ML-KEM-1024")

    # FCC computes X25519 shared secret
    fcc_x_shared_secret = x25519_derive_shared_secret(fcc_x_priv, gcs_x_pub)

    # Validate that both shared secrets match on both sides
    assert gcs_x_shared_secret == fcc_x_shared_secret
    assert gcs_ml_shared_secret == fcc_ml_shared_secret

    # -------------------------------------------------------------
    # Step 6: Derive Hybrid Session Key via HKDF
    # -------------------------------------------------------------
    # Combine X25519 shared secret (32 bytes) + ML-KEM shared secret (32 bytes)
    fcc_hybrid_ikm = fcc_x_shared_secret + fcc_ml_shared_secret
    gcs_hybrid_ikm = gcs_x_shared_secret + gcs_ml_shared_secret
    assert len(fcc_hybrid_ikm) == 64
    assert fcc_hybrid_ikm == gcs_hybrid_ikm

    session_salt = b"AVIONICS_PQC_SESSION_SALT_V1"
    session_info = b"FCC_GCS_SESSION_KEY_AES256"

    fcc_session_key = hkdf_derive(
        ikm=fcc_hybrid_ikm,
        salt=session_salt,
        info=session_info,
        length=32,
        hash_name="SHA256",
    )

    gcs_session_key = hkdf_derive(
        ikm=gcs_hybrid_ikm,
        salt=session_salt,
        info=session_info,
        length=32,
        hash_name="SHA256",
    )

    assert fcc_session_key == gcs_session_key
    assert len(fcc_session_key) == 32

    # -------------------------------------------------------------
    # Step 7: Encrypt and Decrypt Message with AES-256-GCM
    # -------------------------------------------------------------
    aad = b"TELEMETRY_PACKET_ID_0001"
    ciphertext, nonce = aes_gcm_encrypt(
        key=fcc_session_key,
        plaintext=test_message,
        associated_data=aad,
    )

    # Recipient decrypts
    decrypted_message = aes_gcm_decrypt(
        key=gcs_session_key,
        nonce=nonce,
        ciphertext=ciphertext,
        associated_data=aad,
    )

    assert decrypted_message == test_message
    assert decrypted_message.decode("utf-8") == "ALTITUDE=32000FT"
