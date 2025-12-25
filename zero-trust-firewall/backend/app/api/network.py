from fastapi import APIRouter, Depends, HTTPException, status, Query, WebSocket, WebSocketDisconnect
from sqlalchemy.orm import Session
from sqlalchemy import desc, func
from typing import Optional, List
from datetime import datetime, timedelta
import asyncio
import json

from app.core.database import get_db
from app.core.security import get_current_user, get_current_analyst_user
from app.models.user import User
from app.models.threat import NetworkConnection
from app.schemas.threat import NetworkConnectionResponse, NetworkStatsResponse
from app.services.network_monitor import network_monitor

router = APIRouter(prefix="/network", tags=["Network Monitoring"])


# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except:
                pass


manager = ConnectionManager()


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time network monitoring."""
    await manager.connect(websocket)
    try:
        while True:
            # Send real-time stats every second
            stats = network_monitor.get_real_time_stats()
            await websocket.send_json(stats)
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        manager.disconnect(websocket)


@router.get("/connections")
async def get_connections(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    is_blocked: Optional[bool] = None,
    protocol: Optional[str] = None,
    source_ip: Optional[str] = None,
    destination: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get network connection logs."""
    query = db.query(NetworkConnection)

    if is_blocked is not None:
        query = query.filter(NetworkConnection.is_blocked == is_blocked)

    if protocol:
        query = query.filter(NetworkConnection.protocol == protocol)

    if source_ip:
        query = query.filter(NetworkConnection.source_ip.ilike(f"%{source_ip}%"))

    if destination:
        query = query.filter(
            (NetworkConnection.destination_ip.ilike(f"%{destination}%")) |
            (NetworkConnection.destination_domain.ilike(f"%{destination}%"))
        )

    if start_date:
        query = query.filter(NetworkConnection.timestamp >= start_date)

    if end_date:
        query = query.filter(NetworkConnection.timestamp <= end_date)

    total = query.count()
    connections = query.order_by(desc(NetworkConnection.timestamp)).offset(
        (page - 1) * page_size
    ).limit(page_size).all()

    return {
        'items': [NetworkConnectionResponse.model_validate(c) for c in connections],
        'total': total,
        'page': page,
        'page_size': page_size,
        'pages': (total + page_size - 1) // page_size
    }


@router.get("/stats")
async def get_network_stats(
    hours: int = Query(24, ge=1, le=168),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get network statistics."""
    return network_monitor.get_traffic_data(db, hours)


@router.get("/real-time")
async def get_real_time_stats(
    current_user: User = Depends(get_current_user)
):
    """Get real-time network statistics."""
    return network_monitor.get_real_time_stats()


@router.post("/block/{ip}")
async def block_ip(
    ip: str,
    reason: str = "Manual block",
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_analyst_user)
):
    """Block an IP address."""
    result = network_monitor.block_ip(ip, reason)

    # Log the block
    connection = NetworkConnection(
        source_ip=ip,
        is_blocked=True,
        block_reason=reason,
        connection_status='blocked'
    )
    db.add(connection)
    db.commit()

    return result


@router.post("/unblock/{ip}")
async def unblock_ip(
    ip: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_analyst_user)
):
    """Unblock an IP address."""
    return network_monitor.unblock_ip(ip)


@router.get("/blocked")
async def get_blocked_ips(
    current_user: User = Depends(get_current_user)
):
    """Get list of blocked IP addresses."""
    return {
        'blocked_ips': list(network_monitor.blocked_ips),
        'count': len(network_monitor.blocked_ips)
    }


@router.get("/protocols")
async def get_protocol_distribution(
    hours: int = Query(24, ge=1, le=168),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get protocol distribution."""
    start_time = datetime.utcnow() - timedelta(hours=hours)

    results = db.query(
        NetworkConnection.protocol,
        func.count(NetworkConnection.id).label('count'),
        func.sum(NetworkConnection.bytes_sent).label('bytes_sent'),
        func.sum(NetworkConnection.bytes_received).label('bytes_received')
    ).filter(
        NetworkConnection.timestamp >= start_time
    ).group_by(NetworkConnection.protocol).all()

    return [
        {
            'protocol': r.protocol or 'Unknown',
            'count': r.count,
            'bytes_sent': r.bytes_sent or 0,
            'bytes_received': r.bytes_received or 0
        }
        for r in results
    ]


@router.get("/top-destinations")
async def get_top_destinations(
    limit: int = Query(10, ge=1, le=50),
    hours: int = Query(24, ge=1, le=168),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get top network destinations."""
    start_time = datetime.utcnow() - timedelta(hours=hours)

    results = db.query(
        NetworkConnection.destination_domain,
        func.count(NetworkConnection.id).label('count'),
        func.sum(NetworkConnection.bytes_received).label('bytes')
    ).filter(
        NetworkConnection.timestamp >= start_time,
        NetworkConnection.destination_domain.isnot(None)
    ).group_by(
        NetworkConnection.destination_domain
    ).order_by(
        func.count(NetworkConnection.id).desc()
    ).limit(limit).all()

    return [
        {
            'domain': r.destination_domain,
            'connections': r.count,
            'bytes': r.bytes or 0
        }
        for r in results
    ]


@router.get("/bandwidth")
async def get_bandwidth_stats(
    hours: int = Query(24, ge=1, le=168),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """Get bandwidth statistics over time."""
    start_time = datetime.utcnow() - timedelta(hours=hours)

    results = db.query(
        func.date_trunc('hour', NetworkConnection.timestamp).label('hour'),
        func.sum(NetworkConnection.bytes_sent).label('bytes_sent'),
        func.sum(NetworkConnection.bytes_received).label('bytes_received'),
        func.count(NetworkConnection.id).label('connections')
    ).filter(
        NetworkConnection.timestamp >= start_time
    ).group_by(
        func.date_trunc('hour', NetworkConnection.timestamp)
    ).order_by(
        func.date_trunc('hour', NetworkConnection.timestamp)
    ).all()

    return [
        {
            'timestamp': str(r.hour),
            'bytes_sent': r.bytes_sent or 0,
            'bytes_received': r.bytes_received or 0,
            'connections': r.connections
        }
        for r in results
    ]
