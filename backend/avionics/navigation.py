"""Navigation Computer (NAV) Simulated Avionics Entity.

DISCLAIMER: This is a software simulation model designed solely for cryptographic evaluation.
It does NOT connect to or control physical navigation sensors, GPS units, or aircraft systems.
"""

from __future__ import annotations

from typing import Any

from backend.avionics.base import AvionicsEntity, ComponentType
from backend.avionics.messages import (
    AvionicsMessage,
    MessageType,
    create_navigation_update_message,
)


class NavigationComputer(AvionicsEntity):
    """Simulated Navigation Computer (NAV) for AIRCRAFT-001."""

    DEFAULT_NAV_ID = "AIRCRAFT-001-NAV"
    DEFAULT_AIRCRAFT_ID = "AIRCRAFT-001"

    def __init__(
        self,
        component_id: str = DEFAULT_NAV_ID,
        aircraft_id: str = DEFAULT_AIRCRAFT_ID,
        slhdsa_param: str = "shake_128f",
    ):
        super().__init__(
            component_id=component_id,
            component_type=ComponentType.NAVIGATION_COMPUTER,
            aircraft_id=aircraft_id,
            slhdsa_param=slhdsa_param,
        )

    def create_navigation_update(
        self,
        receiver_id: str,
        latitude: float = 37.7749,
        longitude: float = -122.4194,
        altitude_ft: int = 32000,
    ) -> AvionicsMessage:
        """Create a simulated NAVIGATION_UPDATE message."""
        return create_navigation_update_message(
            sender_id=self.component_id,
            receiver_id=receiver_id,
            latitude=latitude,
            longitude=longitude,
            altitude_ft=altitude_ft,
        )

    def get_latest_received_display(self) -> str | None:
        """Return the formatted display string of the latest successfully decrypted message."""
        if not self._received_messages:
            return None
        return self._received_messages[-1].display_string()
