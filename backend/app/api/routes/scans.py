from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db import get_db
from app.models import Scan
from app.schemas import ScanRead

router = APIRouter(prefix="/scans", tags=["scans"])

DbSession = Annotated[Session, Depends(get_db)]


@router.get("", response_model=list[ScanRead])
def list_scans(db: DbSession) -> list[Scan]:
    """List scans, newest first. M0 only — upload pipeline lands in M1."""
    return list(db.scalars(select(Scan).order_by(Scan.created_at.desc())).all())


@router.get("/{scan_id}", response_model=ScanRead)
def get_scan(scan_id: int, db: DbSession) -> Scan:
    scan = db.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return scan
