from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc, func
from typing import Optional, List
from datetime import datetime, timedelta

from app.core.database import get_db
from app.core.security import get_current_user, get_current_analyst_user, get_current_admin_user
from app.models.user import User
from app.models.threat import ThreatIntel, URLScan
from app.schemas.threat import ThreatIntelCreate, ThreatIntelResponse
from app.services.threat_intel import threat_intel

router = APIRouter(prefix="/threats", tags=["Threat Intelligence"])


@router.get("/intel")
async def get_threat_intel(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    indicator_type: Optional[str] = None,
    threat_type: Optional[str] = None,
    severity: Optional[str] = None,
    is_active: Optional[bool] = True,
    search: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get threat intelligence indicators."""
    query = db.query(ThreatIntel)

    if indicator_type:
        query = query.filter(ThreatIntel.indicator_type == indicator_type)

    if threat_type:
        query = query.filter(ThreatIntel.threat_type == threat_type)

    if severity:
        query = query.filter(ThreatIntel.severity == severity)

    if is_active is not None:
        query = query.filter(ThreatIntel.is_active == is_active)

    if search:
        query = query.filter(ThreatIntel.indicator.ilike(f"%{search}%"))

    total = query.count()
    items = query.order_by(desc(ThreatIntel.created_at)).offset(
        (page - 1) * page_size
    ).limit(page_size).all()

    return {
        'items': [ThreatIntelResponse.model_validate(item) for item in items],
        'total': total,
        'page': page,
        'page_size': page_size,
        'pages': (total + page_size - 1) // page_size
    }


@router.post("/intel", response_model=ThreatIntelResponse, status_code=status.HTTP_201_CREATED)
async def add_threat_intel(
    intel_data: ThreatIntelCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_analyst_user)
):
    """Add a new threat intelligence indicator."""
    # Check if indicator already exists
    existing = db.query(ThreatIntel).filter(
        ThreatIntel.indicator == intel_data.indicator.lower()
    ).first()

    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Indicator already exists"
        )

    intel = ThreatIntel(
        indicator=intel_data.indicator.lower(),
        indicator_type=intel_data.indicator_type,
        threat_type=intel_data.threat_type,
        severity=intel_data.severity.value,
        source=intel_data.source,
        description=intel_data.description,
        tags=intel_data.tags,
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow()
    )

    db.add(intel)
    db.commit()
    db.refresh(intel)

    # Update in-memory blacklist
    if intel_data.threat_type != 'whitelist':
        threat_intel.add_to_blacklist(intel_data.indicator)
    else:
        threat_intel.add_to_whitelist(intel_data.indicator)

    return intel


@router.get("/intel/{intel_id}", response_model=ThreatIntelResponse)
async def get_threat_intel_detail(
    intel_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get details of a specific threat indicator."""
    intel = db.query(ThreatIntel).filter(ThreatIntel.id == intel_id).first()

    if not intel:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Threat indicator not found"
        )

    return intel


@router.delete("/intel/{intel_id}")
async def delete_threat_intel(
    intel_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin_user)
):
    """Delete a threat indicator (requires admin role)."""
    intel = db.query(ThreatIntel).filter(ThreatIntel.id == intel_id).first()

    if not intel:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Threat indicator not found"
        )

    # Remove from in-memory lists
    threat_intel.remove_from_blacklist(intel.indicator)
    threat_intel.remove_from_whitelist(intel.indicator)

    db.delete(intel)
    db.commit()

    return {"message": "Threat indicator deleted"}


@router.post("/intel/sync")
async def sync_threat_intel(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_admin_user)
):
    """Sync threat intelligence from external sources."""
    # Update from external blacklist
    update_result = await threat_intel.update_blacklist()

    # Sync from database
    sync_result = await threat_intel.sync_from_database(db)

    return {
        'external_update': update_result,
        'database_sync': sync_result,
        'stats': threat_intel.get_stats()
    }


@router.get("/intel/stats")
async def get_threat_intel_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get threat intelligence statistics."""
    # Database stats
    total_indicators = db.query(ThreatIntel).count()
    active_indicators = db.query(ThreatIntel).filter(ThreatIntel.is_active == True).count()

    # By type
    type_dist = db.query(
        ThreatIntel.indicator_type,
        func.count(ThreatIntel.id)
    ).group_by(ThreatIntel.indicator_type).all()

    # By severity
    severity_dist = db.query(
        ThreatIntel.severity,
        func.count(ThreatIntel.id)
    ).group_by(ThreatIntel.severity).all()

    # Memory stats
    memory_stats = threat_intel.get_stats()

    return {
        'total_indicators': total_indicators,
        'active_indicators': active_indicators,
        'type_distribution': {t[0]: t[1] for t in type_dist if t[0]},
        'severity_distribution': {s[0]: s[1] for s in severity_dist if s[0]},
        'memory_blacklist': memory_stats['blacklist_count'],
        'memory_whitelist': memory_stats['whitelist_count'],
        'last_update': memory_stats['last_update']
    }


@router.get("/top-blocked")
async def get_top_blocked_domains(
    limit: int = Query(10, ge=1, le=50),
    days: int = Query(7, ge=1, le=90),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get top blocked domains."""
    start_date = datetime.utcnow() - timedelta(days=days)

    results = db.query(
        URLScan.domain,
        func.count(URLScan.id).label('count')
    ).filter(
        URLScan.scanned_at >= start_date,
        URLScan.is_phishing == True
    ).group_by(URLScan.domain).order_by(
        func.count(URLScan.id).desc()
    ).limit(limit).all()

    return [
        {'domain': r[0], 'count': r[1]}
        for r in results
    ]


@router.post("/check")
async def check_indicator(
    indicator: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Check if an indicator is in threat intelligence."""
    # Check in-memory
    is_blacklisted = threat_intel.is_blacklisted(indicator)
    is_whitelisted = threat_intel.is_whitelisted(indicator)

    # Check database
    db_record = db.query(ThreatIntel).filter(
        ThreatIntel.indicator == indicator.lower()
    ).first()

    return {
        'indicator': indicator,
        'is_blacklisted': is_blacklisted,
        'is_whitelisted': is_whitelisted,
        'in_database': db_record is not None,
        'database_record': ThreatIntelResponse.model_validate(db_record) if db_record else None
    }
