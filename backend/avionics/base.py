"""Base Avionics Entity and Identity Model.

Defines the common identity structure, cryptographic capabilities, and secure messaging
interfaces for all simulated avionics nodes (FCC, NAV, GCS).
"""

from __future__ import annotations

from enum import Enum
from typing import Any, TYPE_CHECKING

from backend.avionics.channel import EncryptedPacketEnvelope, SimulatedChannel
from backend.avionics.messages import AvionicsMessage
from backend.crypto import (
    AESGCMError,
    AuthenticationTagError,
    Ed25519Error,
    SLHDSAError,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    ed25519_generate_keypair,
    ed25519_sign,
    ed25519_verify,
    slhdsa_generate_keypair,
    slhdsa_sign,
    slhdsa_verify,
)

if TYPE_CHECKING:
    from backend.protocol.handshake import SecureSession


class ComponentType(str, Enum):
    """Types of avionics and ground components."""

    FLIGHT_CONTROL_COMPUTER = "FLIGHT_CONTROL_COMPUTER"
    NAVIGATION_COMPUTER = "NAVIGATION_COMPUTER"
    GROUND_CONTROL_STATION = "GROUND_CONTROL_STATION"


class SessionNotFoundError(Exception):
    """Raised when an operation requires an established session that does not exist."""


class AvionicsEntity:
    """Base class for all simulated avionics and ground entities."""

    def __init__(
        self,
        component_id: str,
        component_type: ComponentType,
        aircraft_id: str | None = None,
        slhdsa_param: str = "shake_128f",
    ):
        self.component_id = str(component_id)
        self.component_type = component_type
        self.aircraft_id = str(aircraft_id) if aircraft_id is not None else None
        self.slhdsa_param = slhdsa_param

        # -------------------------------------------------------------
        # Long-Term Cryptographic Identity
        # -------------------------------------------------------------
        # Classical Digital Signatures (Ed25519)
        self._ed_private_key, self._ed_public_key = ed25519_generate_keypair()

        # Post-Quantum Digital Signatures (SLH-DSA FIPS 205)
        self._slh_secret_key, self._slh_public_key = slhdsa_generate_keypair(self.slhdsa_param)

        # -------------------------------------------------------------
        # Active Secure Sessions
        # -------------------------------------------------------------
        self._secure_sessions: dict[str, Any] = {}
        self._raw_sessions: dict[str, bytes] = {}

        # Message history
        self._received_messages: list[AvionicsMessage] = []
        self._sent_messages: list[AvionicsMessage] = []

    # =================================================================
    # Identity & Public Keys
    # =================================================================

    @property
    def ed25519_public_key(self) -> bytes:
        """Return the long-term Ed25519 public key."""
        return self._ed_public_key

    @property
    def slhdsa_public_key(self) -> bytes:
        """Return the long-term SLH-DSA public key."""
        return self._slh_public_key

    def get_public_identity(self) -> dict[str, Any]:
        """Return identity metadata and public keys for key exchange authentication."""
        return {
            "component_id": self.component_id,
            "component_type": self.component_type.value,
            "aircraft_id": self.aircraft_id,
            "public_keys": {
                "ed25519": self._ed_public_key,
                "slhdsa": self._slh_public_key,
                "slhdsa_param": self.slhdsa_param,
            },
        }

    # =================================================================
    # Digital Signatures
    # =================================================================

    def sign_payload(self, data: bytes) -> dict[str, bytes]:
        """Sign data using both classical (Ed25519) and post-quantum (SLH-DSA) keys.

        Args:
            data: Raw payload bytes to sign.

        Returns:
            dict[str, bytes]: {"ed25519": ed_sig, "slhdsa": slh_sig}
        """
        ed_sig = ed25519_sign(self._ed_private_key, data)
        slh_sig = slhdsa_sign(self._slh_secret_key, data, parameter_set=self.slhdsa_param)
        return {"ed25519": ed_sig, "slhdsa": slh_sig}

    @staticmethod
    def verify_peer_signatures(
        data: bytes,
        signatures: dict[str, bytes],
        peer_public_keys: dict[str, bytes],
        slhdsa_param: str = "shake_128f",
    ) -> bool:
        """Verify hybrid Ed25519 + SLH-DSA signatures on payload.

        Args:
            data: Payload bytes.
            signatures: Dict containing 'ed25519' and 'slhdsa' signatures.
            peer_public_keys: Dict containing 'ed25519' and 'slhdsa' public keys.
            slhdsa_param: SLH-DSA parameter set name.

        Returns:
            bool: True if both classical and post-quantum signatures verify successfully.
        """
        if "ed25519" not in signatures or "slhdsa" not in signatures:
            return False
        if "ed25519" not in peer_public_keys or "slhdsa" not in peer_public_keys:
            return False

        ed_valid = ed25519_verify(peer_public_keys["ed25519"], data, signatures["ed25519"])
        slh_valid = slhdsa_verify(peer_public_keys["slhdsa"], data, signatures["slhdsa"], slhdsa_param)
        return ed_valid and slh_valid

    # =================================================================
    # Session Management
    # =================================================================

    def register_secure_session(self, peer_id: str, session: Any) -> None:
        """Store an established SecureSession instance for a peer."""
        self._secure_sessions[str(peer_id)] = session
        if hasattr(session, "session_key"):
            self._raw_sessions[str(peer_id)] = session.session_key

    def get_secure_session(self, peer_id: str) -> Any | None:
        """Get the established SecureSession for a peer."""
        return self._secure_sessions.get(str(peer_id))

    def register_session(self, peer_id: str, session_key: bytes) -> None:
        """Store an established 32-byte AES-256 raw session key for backwards compatibility."""
        if not isinstance(session_key, (bytes, bytearray)) or len(session_key) != 32:
            raise ValueError(f"Session key must be a 32-byte binary key, got {len(session_key) if hasattr(session_key, '__len__') else 'invalid'}")
        self._raw_sessions[str(peer_id)] = bytes(session_key)

    def has_session(self, peer_id: str) -> bool:
        """Check if an active session exists for the given peer."""
        return str(peer_id) in self._secure_sessions or str(peer_id) in self._raw_sessions

    def remove_session(self, peer_id: str) -> None:
        """Remove established session for a peer."""
        self._secure_sessions.pop(str(peer_id), None)
        self._raw_sessions.pop(str(peer_id), None)

    def establish_secure_session(
        self,
        peer: AvionicsEntity,
        mlkem_param: str = "ML-KEM-1024",
        slhdsa_param: str = "shake_128f",
    ) -> Any:
        """Initiate and perform a secure hybrid handshake with a peer entity.

        Args:
            peer: Target AvionicsEntity.
            mlkem_param: ML-KEM parameter set name.
            slhdsa_param: SLH-DSA parameter set name.

        Returns:
            SecureSession: Established secure session for this entity.
        """
        from backend.protocol.handshake import perform_handshake

        local_session, peer_session = perform_handshake(
            initiator=self,
            responder=peer,
            mlkem_param=mlkem_param,
            slhdsa_param=slhdsa_param,
        )
        return local_session

    # =================================================================
    # Encrypted Messaging (AEAD AES-256-GCM)
    # =================================================================

    def encrypt_message(
        self,
        receiver_id: str,
        message: AvionicsMessage,
        associated_data: bytes | None = None,
    ) -> EncryptedPacketEnvelope:
        """Encrypt an avionics message for a peer using the established secure session.

        Args:
            receiver_id: ID of the intended recipient.
            message: AvionicsMessage instance.
            associated_data: Optional Additional Authenticated Data (used only for raw sessions).

        Returns:
            EncryptedPacketEnvelope: Opaque encrypted envelope.

        Raises:
            SessionNotFoundError: If no active session exists with receiver_id.
            AESGCMError: If encryption fails.
        """
        if not self.has_session(receiver_id):
            raise SessionNotFoundError(f"No active secure session established between {self.component_id} and {receiver_id}")

        if receiver_id in self._secure_sessions:
            session = self._secure_sessions[receiver_id]
            envelope = session.encrypt_message(message)
            self._sent_messages.append(message)
            return envelope

        # Raw key session fallback
        session_key = self._raw_sessions[receiver_id]
        plaintext = message.to_bytes()

        ciphertext, nonce = aes_gcm_encrypt(
            key=session_key,
            plaintext=plaintext,
            associated_data=associated_data,
        )

        self._sent_messages.append(message)

        return EncryptedPacketEnvelope(
            sender_id=self.component_id,
            receiver_id=receiver_id,
            nonce=nonce,
            ciphertext=ciphertext,
            associated_data=associated_data,
        )

    def decrypt_message(self, envelope: EncryptedPacketEnvelope) -> AvionicsMessage:
        """Decrypt and verify an incoming encrypted packet envelope.

        Args:
            envelope: EncryptedPacketEnvelope received from channel.

        Returns:
            AvionicsMessage: Decrypted and validated message.

        Raises:
            SessionNotFoundError: If no active session exists with sender.
            AuthenticationTagError: If packet has been tampered with or corrupted.
            ValueError: If message deserialization fails.
        """
        sender_id = envelope.sender_id
        if not self.has_session(sender_id):
            raise SessionNotFoundError(f"No active secure session established with sender {sender_id}")

        if sender_id in self._secure_sessions:
            session = self._secure_sessions[sender_id]
            message = session.decrypt_message(envelope)
            self._received_messages.append(message)
            return message

        # Raw key session fallback
        session_key = self._raw_sessions[sender_id]

        plaintext = aes_gcm_decrypt(
            key=session_key,
            nonce=envelope.nonce,
            ciphertext=envelope.ciphertext,
            associated_data=envelope.associated_data,
        )

        message = AvionicsMessage.from_bytes(plaintext)
        self._received_messages.append(message)
        return message

    def send_via_channel(
        self,
        receiver_id: str,
        message: AvionicsMessage,
        channel: SimulatedChannel,
        associated_data: bytes | None = None,
    ) -> EncryptedPacketEnvelope:
        """Helper to encrypt and transmit an avionics message across an untrusted channel."""
        envelope = self.encrypt_message(receiver_id, message, associated_data=associated_data)
        return channel.transmit(envelope)

    @property
    def received_messages(self) -> list[AvionicsMessage]:
        """Return list of decrypted messages received by this component."""
        return list(self._received_messages)

    @property
    def sent_messages(self) -> list[AvionicsMessage]:
        """Return list of messages sent by this component."""
        return list(self._sent_messages)
