"""Ground Control Station (GCS) Simulated Ground Entity.

DISCLAIMER: This is a software simulation model designed solely for cryptographic evaluation.
It does NOT interface with real air traffic control or ground station telecommunications hardware.
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


class GroundControlStation(AvionicsEntity):
    """Simulated Ground Control Station (GCS)."""

    DEFAULT_GCS_ID = "GROUND-STATION-001"

    def __init__(
        self,
        component_id: str = DEFAULT_GCS_ID,
        slhdsa_param: str = "shake_128f",
    ):
        super().__init__(
            component_id=component_id,
            component_type=ComponentType.GROUND_CONTROL_STATION,
            aircraft_id=None,
            slhdsa_param=slhdsa_param,
        )

    def create_command_message(
        self,
        receiver_id: str,
        message_type: MessageType,
        payload: dict[str, Any],
    ) -> AvionicsMessage:
        """Create a generic ground command message."""
        return AvionicsMessage(
            sender_id=self.component_id,
            receiver_id=receiver_id,
            message_type=message_type,
            payload=payload,
        )
