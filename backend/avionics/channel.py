"""Simulated Untrusted Communication Channel.

Provides a software abstraction of the untrusted physical or datalink network
connecting aircraft avionics components and ground control stations.

CRITICAL SECURITY DESIGN:
- The channel only routes and transports opaque encrypted packet envelopes.
- The channel has NO access to cryptographic keys and CANNOT decrypt or inspect plaintext payloads.
- Represents the untrusted transport layer (e.g. VHF Datalink, SATCOM, ARINC 429/AFDX bus simulation).
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable


@dataclass(frozen=True)
class EncryptedPacketEnvelope:
    """Opaque packet envelope transported over the untrusted communication channel."""

    packet_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    sender_id: str = ""
    receiver_id: str = ""
    nonce: bytes = b""
    ciphertext: bytes = b""
    associated_data: bytes | None = None
    timestamp: float = field(default_factory=time.time)

    def size_bytes(self) -> int:
        """Calculate total payload size of the encrypted packet in bytes."""
        aad_len = len(self.associated_data) if self.associated_data is not None else 0
        return len(self.nonce) + len(self.ciphertext) + aad_len


class SimulatedChannel:
    """Untrusted communication channel for transmitting encrypted packets."""

    def __init__(self, name: str = "UNTRUSTED_DATALINK"):
        self.name = name
        self._traffic_log: list[dict[str, Any]] = []
        self._subscribers: dict[str, list[Callable[[EncryptedPacketEnvelope], None]]] = {}

    def subscribe(self, component_id: str, callback: Callable[[EncryptedPacketEnvelope], None]) -> None:
        """Register a delivery callback for a given component ID."""
        if component_id not in self._subscribers:
            self._subscribers[component_id] = []
        self._subscribers[component_id].append(callback)

    def transmit(self, envelope: EncryptedPacketEnvelope) -> EncryptedPacketEnvelope:
        """Transmit an encrypted packet envelope across the channel.

        The channel records transmission metadata without possessing the ability
        to decrypt the ciphertext.

        Args:
            envelope: Encrypted packet envelope.

        Returns:
            EncryptedPacketEnvelope: The delivered envelope.

        Raises:
            TypeError: If envelope is not an EncryptedPacketEnvelope.
        """
        if not isinstance(envelope, EncryptedPacketEnvelope):
            raise TypeError(f"Channel can only transport EncryptedPacketEnvelope, got {type(envelope).__name__}")

        # Log metadata only (NO decryption occurs)
        log_entry = {
            "packet_id": envelope.packet_id,
            "sender_id": envelope.sender_id,
            "receiver_id": envelope.receiver_id,
            "nonce_len": len(envelope.nonce),
            "ciphertext_len": len(envelope.ciphertext),
            "aad_present": envelope.associated_data is not None,
            "timestamp": envelope.timestamp,
        }
        self._traffic_log.append(log_entry)

        # Deliver to any registered subscriber callbacks for the receiver
        if envelope.receiver_id in self._subscribers:
            for callback in self._subscribers[envelope.receiver_id]:
                callback(envelope)

        return envelope

    @property
    def total_packets_transmitted(self) -> int:
        """Return total number of packets transmitted through this channel."""
        return len(self._traffic_log)

    @property
    def traffic_log(self) -> list[dict[str, Any]]:
        """Return a copy of the channel traffic log."""
        return list(self._traffic_log)

    def clear_log(self) -> None:
        """Clear traffic log history."""
        self._traffic_log.clear()
