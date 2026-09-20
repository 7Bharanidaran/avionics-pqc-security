"""Simulated Avionics and Ground Entities Package.

Exposes models, communication channel abstractions, and component classes for:
- Flight Control Computer (FCC)
- Navigation Computer (NAV)
- Ground Control Station (GCS)
"""

from __future__ import annotations

from .base import (
    AvionicsEntity,
    ComponentType,
    SessionNotFoundError,
)
from .channel import (
    EncryptedPacketEnvelope,
    SimulatedChannel,
)
from .fcc import FlightControlComputer
from .ground_station import GroundControlStation
from .messages import (
    AvionicsMessage,
    MessageType,
    create_aircraft_status_message,
    create_altitude_message,
    create_flight_mode_message,
    create_heading_message,
    create_navigation_update_message,
)
from .navigation import NavigationComputer

__all__ = [
    # Base
    "AvionicsEntity",
    "ComponentType",
    "SessionNotFoundError",
    # Channel
    "EncryptedPacketEnvelope",
    "SimulatedChannel",
    # Components
    "FlightControlComputer",
    "NavigationComputer",
    "GroundControlStation",
    # Messages
    "AvionicsMessage",
    "MessageType",
    "create_altitude_message",
    "create_heading_message",
    "create_flight_mode_message",
    "create_aircraft_status_message",
    "create_navigation_update_message",
]
