from __future__ import annotations

from fastapi import APIRouter

from app.config_schema import ConfigSchemaEnvelope, export_machine_schema

router = APIRouter(prefix='/config', tags=['config'])


@router.get('/schema', response_model=ConfigSchemaEnvelope)
def get_config_schema() -> ConfigSchemaEnvelope:
    return export_machine_schema()
