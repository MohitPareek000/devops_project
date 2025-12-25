from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, desc, case, Integer
from datetime import datetime, timedelta
from typing import Optional

from app.core.database import get_db
from app.core.security import get_current_user
from app.models.user import User
from app.models.threat import URLScan, Alert, NetworkConnection, ThreatIntel
from app.schemas.threat import DashboardResponse, DashboardStats, ThreatTrend, URLScanResponse
from app.services.threat_intel import threat_intel

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/stats")
async def get_dashboard_stats(
    days: int = Query(7, ge=1, le=90),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get main dashboard statistics."""
    start_date = datetime.utcnow() - timedelta(days=days)

    # Total scans
    total_scans = db.query(URLScan).filter(
        URLScan.scanned_at >= start_date
    ).count()

    # Phishing detected
    phishing_detected = db.query(URLScan).filter(
        URLScan.scanned_at >= start_date,
        URLScan.is_phishing == True
    ).count()

    # Blocked threats
    blocked_threats = db.query(URLScan).filter(
        URLScan.scanned_at >= start_date,
        URLScan.status == 'blocked'
    ).count()

    # Active alerts
    active_alerts = db.query(Alert).filter(
        Alert.is_acknowledged == False
    ).count()

    # Calculate rates
    previous_period_start = start_date - timedelta(days=days)
    previous_scans = db.query(URLScan).filter(
        URLScan.scanned_at >= previous_period_start,
        URLScan.scanned_at < start_date
    ).count()

    scan_rate = ((total_scans - previous_scans) / max(previous_scans, 1)) * 100 if previous_scans else 0
    detection_rate = (phishing_detected / max(total_scans, 1)) * 100

    return DashboardStats(
        total_scans=total_scans,
        phishing_detected=phishing_detected,
        blocked_threats=blocked_threats,
        active_alerts=active_alerts,
        scan_rate=round(scan_rate, 2),
        detection_rate=round(detection_rate, 2)
    )


@router.get("/severity-distribution")
async def get_severity_distribution(
    days: int = Query(7, ge=1, le=90),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get threat severity distribution."""
    start_date = datetime.utcnow() - timedelta(days=days)

    results = db.query(
        URLScan.severity,
        func.count(URLScan.id)
    ).filter(
        URLScan.scanned_at >= start_date
    ).group_by(URLScan.severity).all()

    distribution = {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0,
        'info': 0
    }

    for severity, count in results:
        if severity in distribution:
            distribution[severity] = count

    return distribution


@router.get("/trends")
async def get_threat_trends(
    days: int = Query(7, ge=1, le=30),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get threat trends over time."""
    start_date = datetime.utcnow() - timedelta(days=days)

    # Get daily data - use case for cross-database compatibility
    results = db.query(
        func.date(URLScan.scanned_at).label('date'),
        func.count(URLScan.id).label('total'),
        func.sum(case((URLScan.is_phishing == True, 1), else_=0)).label('phishing')
    ).filter(
        URLScan.scanned_at >= start_date
    ).group_by(
        func.date(URLScan.scanned_at)
    ).order_by(
        func.date(URLScan.scanned_at)
    ).all()

    trends = []
    for row in results:
        trends.append(ThreatTrend(
            date=str(row.date),
            total=row.total or 0,
            phishing=int(row.phishing or 0),
            blocked=int(row.phishing or 0)  # Assuming all phishing is blocked
        ))

    return trends


@router.get("/recent-threats")
async def get_recent_threats(
    limit: int = Query(10, ge=1, le=50),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get recent threat detections."""
    threats = db.query(URLScan).filter(
        URLScan.is_phishing == True
    ).order_by(
        desc(URLScan.scanned_at)
    ).limit(limit).all()

    return [URLScanResponse.model_validate(t) for t in threats]


@router.get("/top-blocked-domains")
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
        func.count(URLScan.id).label('count'),
        func.max(URLScan.severity).label('max_severity')
    ).filter(
        URLScan.scanned_at >= start_date,
        URLScan.is_phishing == True,
        URLScan.domain.isnot(None)
    ).group_by(URLScan.domain).order_by(
        func.count(URLScan.id).desc()
    ).limit(limit).all()

    return [
        {
            'domain': r.domain,
            'count': r.count,
            'severity': r.max_severity
        }
        for r in results
    ]


@router.get("/activity-timeline")
async def get_activity_timeline(
    hours: int = Query(24, ge=1, le=168),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get activity timeline by hour."""
    start_time = datetime.utcnow() - timedelta(hours=hours)

    # URL Scans by hour - simplified for SQLite compatibility
    scan_results = db.query(
        func.strftime('%Y-%m-%d %H:00', URLScan.scanned_at).label('hour'),
        func.count(URLScan.id).label('scans'),
        func.sum(case((URLScan.is_phishing == True, 1), else_=0)).label('threats')
    ).filter(
        URLScan.scanned_at >= start_time
    ).group_by(
        func.strftime('%Y-%m-%d %H:00', URLScan.scanned_at)
    ).all()

    # Network connections by hour
    network_results = db.query(
        func.strftime('%Y-%m-%d %H:00', NetworkConnection.timestamp).label('hour'),
        func.count(NetworkConnection.id).label('connections'),
        func.sum(case((NetworkConnection.is_blocked == True, 1), else_=0)).label('blocked')
    ).filter(
        NetworkConnection.timestamp >= start_time
    ).group_by(
        func.strftime('%Y-%m-%d %H:00', NetworkConnection.timestamp)
    ).all()

    # Combine data
    timeline = {}
    for row in scan_results:
        hour_key = str(row.hour)
        if hour_key not in timeline:
            timeline[hour_key] = {'hour': hour_key, 'scans': 0, 'threats': 0, 'connections': 0, 'blocked': 0}
        timeline[hour_key]['scans'] = row.scans or 0
        timeline[hour_key]['threats'] = int(row.threats or 0)

    for row in network_results:
        hour_key = str(row.hour)
        if hour_key not in timeline:
            timeline[hour_key] = {'hour': hour_key, 'scans': 0, 'threats': 0, 'connections': 0, 'blocked': 0}
        timeline[hour_key]['connections'] = row.connections or 0
        timeline[hour_key]['blocked'] = int(row.blocked or 0)

    return sorted(timeline.values(), key=lambda x: x['hour'])


@router.get("/system-health")
async def get_system_health(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get system health status."""
    # Check database
    try:
        db.execute("SELECT 1")
        db_status = "healthy"
    except:
        db_status = "unhealthy"

    # Get threat intel status
    intel_stats = threat_intel.get_stats()

    # Count recent errors (last hour)
    last_hour = datetime.utcnow() - timedelta(hours=1)
    recent_critical = db.query(Alert).filter(
        Alert.created_at >= last_hour,
        Alert.severity == 'critical'
    ).count()

    return {
        'status': 'healthy' if recent_critical < 10 else 'degraded',
        'database': db_status,
        'threat_intel': {
            'status': 'healthy',
            'blacklist_size': intel_stats['blacklist_count'],
            'whitelist_size': intel_stats['whitelist_count'],
            'last_update': intel_stats['last_update']
        },
        'alerts': {
            'critical_last_hour': recent_critical
        },
        'timestamp': datetime.utcnow().isoformat()
    }


@router.get("/summary")
async def get_dashboard_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get complete dashboard summary."""
    # Get all dashboard data in one call
    stats = await get_dashboard_stats(days=7, db=db, current_user=current_user)
    severity = await get_severity_distribution(days=7, db=db, current_user=current_user)
    trends = await get_threat_trends(days=7, db=db, current_user=current_user)
    recent = await get_recent_threats(limit=5, db=db, current_user=current_user)
    top_blocked = await get_top_blocked_domains(limit=5, days=7, db=db, current_user=current_user)
    health = await get_system_health(db=db, current_user=current_user)

    return DashboardResponse(
        stats=stats,
        severity_distribution=severity,
        recent_threats=recent,
        threat_trends=trends,
        top_blocked_domains=top_blocked
    )
