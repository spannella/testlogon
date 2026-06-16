"""PMD-003 — Portfolio dashboard router.

Prefix: /ui/portfolio

All endpoints are read-only GET operations using require_ui_session.
Service calls are wrapped in asyncio.to_thread to avoid blocking the
FastAPI event loop during DynamoDB scans (mirrors google_drive_integration).

RPT-007 dashlet provider (_provider_portfolio_summary) is registered
conditionally in crm_dashlet_data.py when that module is present.
"""
from __future__ import annotations

import asyncio
from typing import Optional

from fastapi import APIRouter, Depends, Query

import app.services.portfolio_dashboard as portfolio_dashboard
from app.models import PortfolioKpisOut, RentSnapshotOut, PriorityItemsOut
from app.services.sessions import require_ui_session

portfolio_dashboard_router = APIRouter(
    prefix="/ui/portfolio",
    tags=["portfolio-dashboard"],
)


@portfolio_dashboard_router.get("/kpis", response_model=PortfolioKpisOut)
async def get_portfolio_kpis(session=Depends(require_ui_session)):
    """Return four headline portfolio KPIs for the authenticated landlord."""
    return await asyncio.to_thread(
        portfolio_dashboard.compute_kpis,
        session["user_sub"],
    )


@portfolio_dashboard_router.get("/rent-snapshot", response_model=RentSnapshotOut)
async def get_rent_snapshot(
    year: int = Query(..., ge=2000, le=2100),
    month: int = Query(..., ge=1, le=12),
    session=Depends(require_ui_session),
):
    """Return monthly rent totals (collected/outstanding/overdue/charged)."""
    return await asyncio.to_thread(
        portfolio_dashboard.monthly_rent_snapshot,
        session["user_sub"],
        year=year,
        month=month,
    )


@portfolio_dashboard_router.get("/priority-items", response_model=PriorityItemsOut)
async def get_priority_items(
    limit: int = Query(20, ge=1, le=100),
    session=Depends(require_ui_session),
):
    """Return upcoming lease expirations and open work orders/tickets."""
    return await asyncio.to_thread(
        portfolio_dashboard.priority_items,
        session["user_sub"],
        limit=limit,
    )
