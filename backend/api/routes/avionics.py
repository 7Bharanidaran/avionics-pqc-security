"""Avionics entities API routes."""

from __future__ import annotations

from typing import Any
from fastapi import APIRouter, HTTPException

from backend.api.schemas import AvionicsEntityResponse, AvionicsListResponse
from backend.avionics import (
    AvionicsEntity,
    FlightControlComputer,
    GroundControlStation,
    NavigationComputer,
)

router = APIRouter(prefix="/avionics", tags=["Avionics"])

# In-memory singleton simulated entities to preserve cryptographic identities
_FCC_INSTANCE = FlightControlComputer()
_NAV_INSTANCE = NavigationComputer()
_GCS_INSTANCE = GroundControlStation()

_ENTITY_REGISTRY: dict[str, AvionicsEntity] = {
    _FCC_INSTANCE.component_id: _FCC_INSTANCE,
    _NAV_INSTANCE.component_id: _NAV_INSTANCE,
    _GCS_INSTANCE.component_id: _GCS_INSTANCE,
}

_ALIAS_MAP: dict[str, str] = {
    "fcc": _FCC_INSTANCE.component_id,
    "nav": _NAV_INSTANCE.component_id,
    "gcs": _GCS_INSTANCE.component_id,
    "fcc_computer": _FCC_INSTANCE.component_id,
    "nav_computer": _NAV_INSTANCE.component_id,
    "ground_station": _GCS_INSTANCE.component_id,
}


def entity_to_response(entity: AvionicsEntity) -> AvionicsEntityResponse:
    """Convert an AvionicsEntity instance to a safe public schema model."""
    name_map = {
        FlightControlComputer: "Flight Control Computer (FCC)",
        NavigationComputer: "Navigation Computer (NAV)",
        GroundControlStation: "Ground Control Station (GCS)",
    }
    role_map = {
        FlightControlComputer: "Primary flight control and telemetry coordinator",
        NavigationComputer: "Inertial navigation, GPS, and route processing",
        GroundControlStation: "Ground telemetry monitor and flight command center",
    }

    name = name_map.get(type(entity), entity.component_id)
    role = role_map.get(type(entity), "Simulated avionics node")

    # Format public keys as hex strings
    pub_keys_hex = {
        "ed25519": entity.ed25519_public_key.hex(),
        "slhdsa": entity.slhdsa_public_key.hex(),
        "slhdsa_param": entity.slhdsa_param,
    }

    return AvionicsEntityResponse(
        id=entity.component_id,
        name=name,
        role=role,
        component_type=entity.component_type.value,
        aircraft_id=entity.aircraft_id,
        status="ACTIVE",
        public_keys=pub_keys_hex,
    )


def resolve_entity(identifier: str) -> AvionicsEntity | None:
    """Resolve an avionics entity by component_id or common alias."""
    norm_id = identifier.strip()
    if norm_id in _ENTITY_REGISTRY:
        return _ENTITY_REGISTRY[norm_id]
    alias_target = _ALIAS_MAP.get(norm_id.lower())
    if alias_target and alias_target in _ENTITY_REGISTRY:
        return _ENTITY_REGISTRY[alias_target]
    return None


@router.get("", response_model=AvionicsListResponse)
def list_avionics_entities() -> AvionicsListResponse:
    """List all simulated avionics entities and their public cryptographic identities."""
    entities = [entity_to_response(e) for e in _ENTITY_REGISTRY.values()]
    return AvionicsListResponse(entities=entities)


@router.get("/fcc", response_model=AvionicsEntityResponse)
def get_fcc_entity() -> AvionicsEntityResponse:
    """Get Flight Control Computer (FCC) identity and public keys."""
    return entity_to_response(_FCC_INSTANCE)


@router.get("/nav", response_model=AvionicsEntityResponse)
def get_nav_entity() -> AvionicsEntityResponse:
    """Get Navigation Computer (NAV) identity and public keys."""
    return entity_to_response(_NAV_INSTANCE)


@router.get("/gcs", response_model=AvionicsEntityResponse)
def get_gcs_entity() -> AvionicsEntityResponse:
    """Get Ground Control Station (GCS) identity and public keys."""
    return entity_to_response(_GCS_INSTANCE)


@router.get("/{component_id}", response_model=AvionicsEntityResponse)
def get_entity_by_id(component_id: str) -> AvionicsEntityResponse:
    """Get public metadata for a specific avionics component by ID or alias."""
    entity = resolve_entity(component_id)
    if entity is None:
        raise HTTPException(
            status_code=404,
            detail=f"Avionics entity '{component_id}' not found in simulation registry.",
        )
    return entity_to_response(entity)
