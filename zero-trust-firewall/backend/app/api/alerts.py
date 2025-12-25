from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import desc, func
from typing import Optional, List
from datetime import datetime, timedelta

from app.core.database import get_db
from app.core.security import get_current_user, get_current_analyst_user
from app.models.user import User
from app.models.threat import Alert
from app.schemas.threat import AlertCreate, AlertResponse, AlertUpdate

router = APIRouter(prefix="/alerts", tags=["Alerts"])


@router.get("/")
async def get_alerts(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    severity: Optional[str] = None,
    alert_type: Optional[str] = None,
    is_read: Optional[bool] = None,
    is_acknowledged: Optional[bool] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get paginated alerts with filters."""
    query = db.query(Alert)

    if severity:
        query = query.filter(Alert.severity == severity)

    if alert_type:
        query = query.filter(Alert.alert_type == alert_type)

    if is_read is not None:
        query = query.filter(Alert.is_read == is_read)

    if is_acknowledged is not None:
        query = query.filter(Alert.is_acknowledged == is_acknowledged)

    if start_date:
        query = query.filter(Alert.created_at >= start_date)

    if end_date:
        query = query.filter(Alert.created_at <= end_date)

    total = query.count()
    alerts = query.order_by(desc(Alert.created_at)).offset(
        (page - 1) * page_size
    ).limit(page_size).all()

    return {
        'items': [AlertResponse.model_validate(a) for a in alerts],
        'total': total,
        'page': page,
        'page_size': page_size,
        'pages': (total + page_size - 1) // page_size
    }


@router.get("/unread")
async def get_unread_alerts(
    limit: int = Query(10, ge=1, le=50),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get unread alerts."""
    alerts = db.query(Alert).filter(
        Alert.is_read == False
    ).order_by(
        desc(Alert.created_at)
    ).limit(limit).all()

    unread_count = db.query(Alert).filter(Alert.is_read == False).count()

    return {
        'alerts': [AlertResponse.model_validate(a) for a in alerts],
        'unread_count': unread_count
    }


@router.get("/count")
async def get_alert_counts(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get alert counts by severity and status."""
    # By severity
    severity_counts = db.query(
        Alert.severity,
        func.count(Alert.id)
    ).filter(
        Alert.is_acknowledged == False
    ).group_by(Alert.severity).all()

    # By type
    type_counts = db.query(
        Alert.alert_type,
        func.count(Alert.id)
    ).filter(
        Alert.is_acknowledged == False
    ).group_by(Alert.alert_type).all()

    # Total counts
    total = db.query(Alert).count()
    unread = db.query(Alert).filter(Alert.is_read == False).count()
    unacknowledged = db.query(Alert).filter(Alert.is_acknowledged == False).count()

    return {
        'total': total,
        'unread': unread,
        'unacknowledged': unacknowledged,
        'by_severity': {s[0]: s[1] for s in severity_counts if s[0]},
        'by_type': {t[0]: t[1] for t in type_counts if t[0]}
    }


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get a specific alert."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()

    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found"
        )

    return alert


@router.patch("/{alert_id}")
async def update_alert(
    alert_id: int,
    update_data: AlertUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Update an alert (mark as read/acknowledged)."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()

    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found"
        )

    if update_data.is_read is not None:
        alert.is_read = update_data.is_read

    if update_data.is_acknowledged is not None:
        alert.is_acknowledged = update_data.is_acknowledged
        if update_data.is_acknowledged:
            alert.acknowledged_by = current_user.id
            alert.acknowledged_at = datetime.utcnow()

    db.commit()
    db.refresh(alert)

    return AlertResponse.model_validate(alert)


@router.post("/mark-all-read")
async def mark_all_read(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Mark all alerts as read."""
    db.query(Alert).filter(
        Alert.is_read == False
    ).update({'is_read': True})
    db.commit()

    return {"message": "All alerts marked as read"}


@router.post("/acknowledge-all")
async def acknowledge_all(
    severity: Optional[str] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_analyst_user)
):
    """Acknowledge all alerts (optionally filter by severity)."""
    query = db.query(Alert).filter(Alert.is_acknowledged == False)

    if severity:
        query = query.filter(Alert.severity == severity)

    count = query.count()
    query.update({
        'is_acknowledged': True,
        'acknowledged_by': current_user.id,
        'acknowledged_at': datetime.utcnow()
    })
    db.commit()

    return {"message": f"{count} alerts acknowledged"}


@router.delete("/{alert_id}")
async def delete_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_analyst_user)
):
    """Delete an alert."""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()

    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found"
        )

    db.delete(alert)
    db.commit()

    return {"message": "Alert deleted"}


@router.post("/", response_model=AlertResponse, status_code=status.HTTP_201_CREATED)
async def create_alert(
    alert_data: AlertCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_analyst_user)
):
    """Create a new alert manually."""
    alert = Alert(
        title=alert_data.title,
        description=alert_data.description,
        severity=alert_data.severity.value,
        alert_type=alert_data.alert_type,
        source=alert_data.source or "Manual",
        metadata=alert_data.metadata,
        user_id=current_user.id
    )

    db.add(alert)
    db.commit()
    db.refresh(alert)

    return alert


@router.get("/stats/timeline")
async def get_alert_timeline(
    days: int = Query(7, ge=1, le=30),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get alert timeline by day."""
    start_date = datetime.utcnow() - timedelta(days=days)

    results = db.query(
        func.date(Alert.created_at).label('date'),
        Alert.severity,
        func.count(Alert.id).label('count')
    ).filter(
        Alert.created_at >= start_date
    ).group_by(
        func.date(Alert.created_at),
        Alert.severity
    ).order_by(
        func.date(Alert.created_at)
    ).all()

    # Organize by date
    timeline = {}
    for row in results:
        date_str = str(row.date)
        if date_str not in timeline:
            timeline[date_str] = {'date': date_str, 'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        if row.severity in timeline[date_str]:
            timeline[date_str][row.severity] = row.count

    return sorted(timeline.values(), key=lambda x: x['date'])
