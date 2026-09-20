"""Simulated Avionics Message Model and Types.

Provides structured message models for simulated aircraft telemetry and control commands.
Contains metadata such as message IDs, sender/receiver IDs, timestamps, and payloads.

DISCLAIMER: This software is a simulation model for post-quantum cryptographic
evaluation and does NOT interface with or control real aircraft systems.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class MessageType(str, Enum):
    """Simulated avionics message types."""

    ALTITUDE = "ALTITUDE"
    HEADING = "HEADING"
    FLIGHT_MODE = "FLIGHT_MODE"
    AIRCRAFT_STATUS = "AIRCRAFT_STATUS"
    NAVIGATION_UPDATE = "NAVIGATION_UPDATE"


@dataclass(frozen=True)
class AvionicsMessage:
    """Represents a simulated avionics telemetry or command message."""

    message_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    sender_id: str = ""
    receiver_id: str = ""
    timestamp: float = field(default_factory=time.time)
    message_type: MessageType = MessageType.AIRCRAFT_STATUS
    payload: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert the message to a serializable dictionary."""
        return {
            "message_id": self.message_id,
            "sender_id": self.sender_id,
            "receiver_id": self.receiver_id,
            "timestamp": self.timestamp,
            "message_type": self.message_type.value,
            "payload": self.payload,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AvionicsMessage:
        """Create an AvionicsMessage from a dictionary.

        Args:
            data: Dictionary containing message fields.

        Returns:
            AvionicsMessage instance.

        Raises:
            ValueError: If required fields or message type are invalid.
        """
        required_fields = {"message_id", "sender_id", "receiver_id", "timestamp", "message_type", "payload"}
        missing = required_fields - set(data.keys())
        if missing:
            raise ValueError(f"Missing required message fields: {missing}")

        try:
            msg_type = MessageType(data["message_type"])
        except ValueError as exc:
            raise ValueError(f"Invalid message type '{data['message_type']}'") from exc

        return cls(
            message_id=str(data["message_id"]),
            sender_id=str(data["sender_id"]),
            receiver_id=str(data["receiver_id"]),
            timestamp=float(data["timestamp"]),
            message_type=msg_type,
            payload=dict(data["payload"]),
        )

    def to_bytes(self) -> bytes:
        """Serialize the message to UTF-8 JSON bytes for encryption."""
        return json.dumps(self.to_dict(), separators=(",", ":"), sort_keys=True).encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes) -> AvionicsMessage:
        """Deserialize an AvionicsMessage from UTF-8 JSON bytes.

        Args:
            data: UTF-8 encoded JSON bytes.

        Returns:
            AvionicsMessage instance.

        Raises:
            ValueError: If parsing or data validation fails.
        """
        if not isinstance(data, (bytes, bytearray)):
            raise TypeError(f"data must be bytes, got {type(data).__name__}")
        try:
            parsed = json.loads(data.decode("utf-8"))
            return cls.from_dict(parsed)
        except Exception as exc:
            raise ValueError(f"Failed to deserialize avionics message: {exc}") from exc

    def display_string(self) -> str:
        """Return a human-readable representation of the message payload."""
        if self.message_type == MessageType.ALTITUDE:
            val = self.payload.get("altitude_ft", "UNKNOWN")
            return f"ALTITUDE = {val} FT"
        elif self.message_type == MessageType.HEADING:
            val = self.payload.get("heading_deg", "UNKNOWN")
            return f"HEADING = {val} DEG"
        elif self.message_type == MessageType.FLIGHT_MODE:
            val = self.payload.get("flight_mode", "UNKNOWN")
            return f"FLIGHT_MODE = {val}"
        elif self.message_type == MessageType.AIRCRAFT_STATUS:
            val = self.payload.get("status", "UNKNOWN")
            return f"AIRCRAFT_STATUS = {val}"
        elif self.message_type == MessageType.NAVIGATION_UPDATE:
            lat = self.payload.get("latitude", "N/A")
            lon = self.payload.get("longitude", "N/A")
            return f"NAVIGATION_UPDATE = LAT:{lat} LON:{lon}"
        return f"{self.message_type.value} = {self.payload}"


# =====================================================================
# Factory helpers for standard simulated avionics messages
# =====================================================================


def create_altitude_message(
    sender_id: str,
    receiver_id: str,
    altitude_ft: int = 32000,
) -> AvionicsMessage:
    """Create an ALTITUDE avionics message."""
    return AvionicsMessage(
        sender_id=sender_id,
        receiver_id=receiver_id,
        message_type=MessageType.ALTITUDE,
        payload={"altitude_ft": int(altitude_ft)},
    )


def create_heading_message(
    sender_id: str,
    receiver_id: str,
    heading_deg: int = 275,
) -> AvionicsMessage:
    """Create a HEADING avionics message."""
    return AvionicsMessage(
        sender_id=sender_id,
        receiver_id=receiver_id,
        message_type=MessageType.HEADING,
        payload={"heading_deg": int(heading_deg)},
    )


def create_flight_mode_message(
    sender_id: str,
    receiver_id: str,
    flight_mode: str = "CRUISE",
) -> AvionicsMessage:
    """Create a FLIGHT_MODE avionics message."""
    return AvionicsMessage(
        sender_id=sender_id,
        receiver_id=receiver_id,
        message_type=MessageType.FLIGHT_MODE,
        payload={"flight_mode": str(flight_mode)},
    )


def create_aircraft_status_message(
    sender_id: str,
    receiver_id: str,
    status: str = "NOMINAL",
) -> AvionicsMessage:
    """Create an AIRCRAFT_STATUS avionics message."""
    return AvionicsMessage(
        sender_id=sender_id,
        receiver_id=receiver_id,
        message_type=MessageType.AIRCRAFT_STATUS,
        payload={"status": str(status)},
    )


def create_navigation_update_message(
    sender_id: str,
    receiver_id: str,
    latitude: float = 37.7749,
    longitude: float = -122.4194,
    altitude_ft: int = 32000,
) -> AvionicsMessage:
    """Create a NAVIGATION_UPDATE avionics message."""
    return AvionicsMessage(
        sender_id=sender_id,
        receiver_id=receiver_id,
        message_type=MessageType.NAVIGATION_UPDATE,
        payload={
            "latitude": float(latitude),
            "longitude": float(longitude),
            "altitude_ft": int(altitude_ft),
        },
    )
