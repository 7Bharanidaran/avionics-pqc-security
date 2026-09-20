"""Flight Control Computer (FCC) Simulated Avionics Entity.

DISCLAIMER: This is a software simulation model designed solely for cryptographic evaluation.
It does NOT connect to or control physical flight control actuators, sensors, or aircraft systems.
"""

from __future__ import annotations

from typing import Any

from backend.avionics.base import AvionicsEntity, ComponentType
from backend.avionics.messages import (
    AvionicsMessage,
    MessageType,
    create_aircraft_status_message,
    create_altitude_message,
    create_flight_mode_message,
    create_heading_message,
)


class FlightControlComputer(AvionicsEntity):
    """Simulated Flight Control Computer (FCC) for AIRCRAFT-001."""

    DEFAULT_FCC_ID = "AIRCRAFT-001-FCC"
    DEFAULT_AIRCRAFT_ID = "AIRCRAFT-001"

    def __init__(
        self,
        component_id: str = DEFAULT_FCC_ID,
        aircraft_id: str = DEFAULT_AIRCRAFT_ID,
        slhdsa_param: str = "shake_128f",
    ):
        super().__init__(
            component_id=component_id,
            component_type=ComponentType.FLIGHT_CONTROL_COMPUTER,
            aircraft_id=aircraft_id,
            slhdsa_param=slhdsa_param,
        )

    def create_altitude_message(
        self,
        receiver_id: str,
        altitude_ft: int = 32000,
    ) -> AvionicsMessage:
        """Create a simulated ALTITUDE message from this FCC."""
        return create_altitude_message(
            sender_id=self.component_id,
            receiver_id=receiver_id,
            altitude_ft=altitude_ft,
        )

    def create_heading_message(
        self,
        receiver_id: str,
        heading_deg: int = 275,
    ) -> AvionicsMessage:
        """Create a simulated HEADING message from this FCC."""
        return create_heading_message(
            sender_id=self.component_id,
            receiver_id=receiver_id,
            heading_deg=heading_deg,
        )

    def create_flight_mode_message(
        self,
        receiver_id: str,
        flight_mode: str = "CRUISE",
    ) -> AvionicsMessage:
        """Create a simulated FLIGHT_MODE message from this FCC."""
        return create_flight_mode_message(
            sender_id=self.component_id,
            receiver_id=receiver_id,
            flight_mode=flight_mode,
        )

    def create_status_message(
        self,
        receiver_id: str,
        status: str = "NOMINAL",
    ) -> AvionicsMessage:
        """Create a simulated AIRCRAFT_STATUS message from this FCC."""
        return create_aircraft_status_message(
            sender_id=self.component_id,
            receiver_id=receiver_id,
            status=status,
        )
