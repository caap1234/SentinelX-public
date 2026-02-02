from __future__ import annotations

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session

from app.config import settings
from app.core.bootstrap import seed_admin_user
from app.core.bootstrap_incident_rules import seed_default_incident_rules
from app.core.bootstrap_rules_v2 import seed_default_rules_v2
from app.db import SessionLocal
from app.routers import (
    admin_users,
    alerts,
    api_keys,
    auth,
    dashboard,
    entities,
    events,
    incidents_v2,
    logs,
    rules_v2,
    processes
)

# Routers con nombre que colisiona (settings/admin_maintenance) -> import explícito de su "router"
from app.routers.admin_maintenance import router as admin_maintenance_router
from app.routers.incident_rules import router as incident_rules_router
from app.routers.settings import router as settings_router

app = FastAPI(
    title="SentinelX SIEM API",
    version="0.2.0",
    description="Backend API para SentinelX SIEM (v2).",
)

# CORS: producción + desarrollo
origins = [
    "https://sentinelx.tokyo-03.com",
    "http://127.0.0.1:4321",
    "http://localhost:4321",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup() -> None:
    if not getattr(settings, "INITIAL_ADMIN_EMAIL", None) or not getattr(
        settings, "INITIAL_ADMIN_PASSWORD", None
    ):
        return

    db: Session = SessionLocal()
    try:
        seed_admin_user(
            db=db,
            email=settings.INITIAL_ADMIN_EMAIL,
            password=settings.INITIAL_ADMIN_PASSWORD,
            full_name=getattr(settings, "INITIAL_ADMIN_FULL_NAME", "Admin"),
        )
        seed_default_rules_v2(db)
        seed_default_incident_rules(db)
    finally:
        db.close()


@app.get("/health", tags=["system"])
def health_check():
    return {"status": "ok", "service": "sentinelx-api", "version": "v2"}


# Routers
app.include_router(auth.router)
app.include_router(logs.router)
app.include_router(api_keys.router)
app.include_router(settings_router)
app.include_router(admin_users.router)
app.include_router(admin_maintenance_router)
app.include_router(events.router)
app.include_router(rules_v2.router)
app.include_router(alerts.router)
app.include_router(dashboard.router)
app.include_router(incidents_v2.router)
app.include_router(entities.router)
app.include_router(incident_rules_router)
app.include_router(processes.router)
