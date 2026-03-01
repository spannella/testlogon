from fastapi import FastAPI
from pydantic import BaseModel

from app.routers.config_schema import router as config_schema_router
from app.routers.ops import router as ops_router
from app.routers.sessions import router as sessions_router


class HealthResponse(BaseModel):
    status: str


app = FastAPI(title='Deployment Initializer API', version='0.1.0')
app.include_router(sessions_router)
app.include_router(config_schema_router)
app.include_router(ops_router)


@app.get('/health', response_model=HealthResponse)
def health() -> HealthResponse:
    return HealthResponse(status='ok')
