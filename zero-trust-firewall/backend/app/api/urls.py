from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc
from typing import Optional, List
from datetime import datetime, timedelta

from app.core.database import get_db
from app.core.security import get_current_user, get_current_analyst_user
from app.models.user import User
from app.models.threat import URLScan, ThreatStatus
from app.schemas.threat import (
    URLScanRequest,
    URLScanBatchRequest,
    URLScanResponse,
    URLScanListResponse
)
from app.services.phishing_detector import phishing_detector

router = APIRouter(prefix="/urls", tags=["URL Scanning"])


@router.post("/scan", response_model=dict)
async def scan_url(
    scan_request: URLScanRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_current_user)
):
    """Scan a single URL for phishing indicators."""
    result = phishing_detector.analyze_url(
        url=scan_request.url,
        db=db,
        user_id=current_user.id if current_user else None,
        source_ip=request.client.host,
        user_agent=request.headers.get("user-agent")
    )

    return result


@router.post("/scan/batch", response_model=List[dict])
async def scan_urls_batch(
    scan_request: URLScanBatchRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Scan multiple URLs for phishing indicators."""
    results = []

    for url in scan_request.urls:
        result = phishing_detector.analyze_url(
            url=url,
            db=db,
            user_id=current_user.id,
            source_ip=request.client.host,
            user_agent=request.headers.get("user-agent")
        )
        results.append(result)

    return results


@router.get("/scans", response_model=URLScanListResponse)
async def get_scan_history(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    is_phishing: Optional[bool] = None,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get paginated scan history with filters."""
    query = db.query(URLScan)

    # Apply filters
    if is_phishing is not None:
        query = query.filter(URLScan.is_phishing == is_phishing)

    if severity:
        query = query.filter(URLScan.severity == severity)

    if status:
        query = query.filter(URLScan.status == status)

    if search:
        query = query.filter(
            (URLScan.url.ilike(f"%{search}%")) |
            (URLScan.domain.ilike(f"%{search}%"))
        )

    if start_date:
        query = query.filter(URLScan.scanned_at >= start_date)

    if end_date:
        query = query.filter(URLScan.scanned_at <= end_date)

    # Get total count
    total = query.count()

    # Get paginated results
    scans = query.order_by(desc(URLScan.scanned_at)).offset(
        (page - 1) * page_size
    ).limit(page_size).all()

    return URLScanListResponse(
        items=[URLScanResponse.model_validate(scan) for scan in scans],
        total=total,
        page=page,
        page_size=page_size,
        pages=(total + page_size - 1) // page_size
    )


@router.get("/scans/{scan_id}", response_model=URLScanResponse)
async def get_scan_details(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get details of a specific scan."""
    scan = db.query(URLScan).filter(URLScan.id == scan_id).first()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )

    return scan


@router.patch("/scans/{scan_id}/status")
async def update_scan_status(
    scan_id: int,
    new_status: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_analyst_user)
):
    """Update the status of a scan (requires analyst role)."""
    scan = db.query(URLScan).filter(URLScan.id == scan_id).first()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )

    valid_statuses = [s.value for s in ThreatStatus]
    if new_status not in valid_statuses:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid status. Must be one of: {valid_statuses}"
        )

    scan.status = new_status
    db.commit()

    return {"message": "Status updated", "new_status": new_status}


@router.delete("/scans/{scan_id}")
async def delete_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_analyst_user)
):
    """Delete a scan record (requires analyst role)."""
    scan = db.query(URLScan).filter(URLScan.id == scan_id).first()

    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan not found"
        )

    db.delete(scan)
    db.commit()

    return {"message": "Scan deleted"}


@router.get("/stats")
async def get_scan_stats(
    days: int = Query(7, ge=1, le=90),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get scanning statistics for the specified period."""
    start_date = datetime.utcnow() - timedelta(days=days)

    total_scans = db.query(URLScan).filter(
        URLScan.scanned_at >= start_date
    ).count()

    phishing_detected = db.query(URLScan).filter(
        URLScan.scanned_at >= start_date,
        URLScan.is_phishing == True
    ).count()

    blocked = db.query(URLScan).filter(
        URLScan.scanned_at >= start_date,
        URLScan.status == 'blocked'
    ).count()

    # Severity distribution
    from sqlalchemy import func
    severity_dist = db.query(
        URLScan.severity,
        func.count(URLScan.id)
    ).filter(
        URLScan.scanned_at >= start_date
    ).group_by(URLScan.severity).all()

    return {
        'total_scans': total_scans,
        'phishing_detected': phishing_detected,
        'blocked': blocked,
        'detection_rate': round(phishing_detected / max(total_scans, 1) * 100, 2),
        'severity_distribution': {s[0]: s[1] for s in severity_dist},
        'period_days': days
    }
