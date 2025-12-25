import asyncio
import random
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
from collections import defaultdict
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.models.threat import NetworkConnection, Alert


class NetworkMonitor:
    """Service for monitoring network connections and traffic."""

    def __init__(self):
        self.active_connections: Dict[str, Dict] = {}
        self.connection_stats = defaultdict(int)
        self.blocked_ips: set = set()
        self.suspicious_ips: Dict[str, int] = defaultdict(int)
        self.threshold_requests_per_minute = 100
        self.monitoring = False

    async def start_monitoring(self):
        """Start network monitoring loop."""
        self.monitoring = True
        while self.monitoring:
            await self._simulate_traffic()
            await asyncio.sleep(1)

    def stop_monitoring(self):
        """Stop network monitoring."""
        self.monitoring = False

    async def _simulate_traffic(self):
        """Simulate network traffic for demo purposes."""
        # In production, this would interface with actual network capture
        protocols = ['HTTPS', 'HTTP', 'TCP', 'UDP', 'DNS']
        statuses = ['established', 'closed', 'syn_sent']

        connection = {
            'source_ip': f"192.168.1.{random.randint(1, 254)}",
            'destination_ip': f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}",
            'destination_port': random.choice([80, 443, 8080, 22, 53, 3306]),
            'protocol': random.choice(protocols),
            'bytes_sent': random.randint(100, 10000),
            'bytes_received': random.randint(100, 50000),
            'status': random.choice(statuses),
            'timestamp': datetime.utcnow()
        }

        conn_id = f"{connection['source_ip']}:{connection['destination_ip']}:{connection['destination_port']}"
        self.active_connections[conn_id] = connection
        self.connection_stats[connection['protocol']] += 1

    def get_active_connections(self) -> List[Dict]:
        """Get list of active connections."""
        return list(self.active_connections.values())

    def get_connection_stats(self) -> Dict[str, Any]:
        """Get connection statistics."""
        return {
            'active_count': len(self.active_connections),
            'blocked_count': len(self.blocked_ips),
            'protocol_distribution': dict(self.connection_stats),
            'suspicious_ips': len(self.suspicious_ips)
        }

    def block_ip(self, ip: str, reason: str = "Manual block"):
        """Block an IP address."""
        self.blocked_ips.add(ip)
        return {'ip': ip, 'blocked': True, 'reason': reason}

    def unblock_ip(self, ip: str):
        """Unblock an IP address."""
        self.blocked_ips.discard(ip)
        return {'ip': ip, 'blocked': False}

    def is_blocked(self, ip: str) -> bool:
        """Check if IP is blocked."""
        return ip in self.blocked_ips

    def check_rate_limit(self, ip: str) -> bool:
        """Check if IP exceeds rate limit."""
        self.suspicious_ips[ip] += 1
        if self.suspicious_ips[ip] > self.threshold_requests_per_minute:
            self.block_ip(ip, "Rate limit exceeded")
            return False
        return True

    def get_traffic_data(self, db: Session, hours: int = 24) -> Dict[str, Any]:
        """Get traffic data for the specified time period."""
        start_time = datetime.utcnow() - timedelta(hours=hours)

        # Get connection counts by hour
        hourly_data = db.query(
            func.date_trunc('hour', NetworkConnection.timestamp).label('hour'),
            func.count(NetworkConnection.id).label('count'),
            func.sum(NetworkConnection.bytes_sent).label('bytes_sent'),
            func.sum(NetworkConnection.bytes_received).label('bytes_received')
        ).filter(
            NetworkConnection.timestamp >= start_time
        ).group_by(
            func.date_trunc('hour', NetworkConnection.timestamp)
        ).all()

        # Get protocol distribution
        protocol_dist = db.query(
            NetworkConnection.protocol,
            func.count(NetworkConnection.id)
        ).filter(
            NetworkConnection.timestamp >= start_time
        ).group_by(NetworkConnection.protocol).all()

        # Get top destinations
        top_destinations = db.query(
            NetworkConnection.destination_domain,
            func.count(NetworkConnection.id).label('count')
        ).filter(
            NetworkConnection.timestamp >= start_time,
            NetworkConnection.destination_domain.isnot(None)
        ).group_by(
            NetworkConnection.destination_domain
        ).order_by(
            func.count(NetworkConnection.id).desc()
        ).limit(10).all()

        # Get blocked connections
        blocked_count = db.query(func.count(NetworkConnection.id)).filter(
            NetworkConnection.timestamp >= start_time,
            NetworkConnection.is_blocked == True
        ).scalar()

        return {
            'hourly_data': [
                {
                    'hour': str(row.hour),
                    'connections': row.count,
                    'bytes_sent': row.bytes_sent or 0,
                    'bytes_received': row.bytes_received or 0
                }
                for row in hourly_data
            ],
            'protocol_distribution': {row[0]: row[1] for row in protocol_dist if row[0]},
            'top_destinations': [
                {'domain': row[0], 'count': row[1]}
                for row in top_destinations
            ],
            'total_blocked': blocked_count or 0,
            'blocked_ips': list(self.blocked_ips)
        }

    def get_real_time_stats(self) -> Dict[str, Any]:
        """Get real-time network statistics."""
        total_bytes_sent = sum(c.get('bytes_sent', 0) for c in self.active_connections.values())
        total_bytes_received = sum(c.get('bytes_received', 0) for c in self.active_connections.values())

        return {
            'active_connections': len(self.active_connections),
            'bytes_per_second_sent': total_bytes_sent,
            'bytes_per_second_received': total_bytes_received,
            'blocked_ips_count': len(self.blocked_ips),
            'protocols': dict(self.connection_stats),
            'timestamp': datetime.utcnow().isoformat()
        }

    def log_connection(
        self,
        db: Session,
        source_ip: str,
        destination_ip: str = None,
        destination_domain: str = None,
        destination_port: int = None,
        protocol: str = None,
        bytes_sent: int = 0,
        bytes_received: int = 0,
        is_blocked: bool = False,
        block_reason: str = None,
        threat_score: float = 0.0
    ) -> NetworkConnection:
        """Log a network connection to database."""
        connection = NetworkConnection(
            source_ip=source_ip,
            destination_ip=destination_ip,
            destination_domain=destination_domain,
            destination_port=destination_port,
            protocol=protocol,
            bytes_sent=bytes_sent,
            bytes_received=bytes_received,
            connection_status='established',
            is_blocked=is_blocked,
            block_reason=block_reason,
            threat_score=threat_score
        )
        db.add(connection)
        db.commit()
        db.refresh(connection)
        return connection


# Singleton instance
network_monitor = NetworkMonitor()
