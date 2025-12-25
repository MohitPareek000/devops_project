from sqlalchemy import Column, Integer, String, Float, Boolean, DateTime, Text, JSON, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
import enum
from app.core.database import Base


class ThreatSeverity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ThreatStatus(str, enum.Enum):
    ACTIVE = "active"
    BLOCKED = "blocked"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class URLScan(Base):
    __tablename__ = "url_scans"

    id = Column(Integer, primary_key=True, index=True)
    url = Column(Text, nullable=False)
    domain = Column(String(255), index=True)
    is_phishing = Column(Boolean, default=False)
    confidence_score = Column(Float, default=0.0)
    ml_score = Column(Float, default=0.0)
    rule_score = Column(Float, default=0.0)
    severity = Column(String(20), default=ThreatSeverity.INFO.value)
    status = Column(String(20), default=ThreatStatus.ACTIVE.value)

    # Feature data
    features = Column(JSON)
    matched_rules = Column(JSON)

    # Metadata
    source_ip = Column(String(45))
    user_agent = Column(Text)
    country = Column(String(100))
    city = Column(String(100))

    # Relations
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    user = relationship("User", back_populates="url_scans")

    # Timestamps
    scanned_at = Column(DateTime(timezone=True), server_default=func.now())
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    def __repr__(self):
        return f"<URLScan {self.domain} - Phishing: {self.is_phishing}>"


class ThreatIntel(Base):
    __tablename__ = "threat_intel"

    id = Column(Integer, primary_key=True, index=True)
    indicator = Column(String(500), unique=True, index=True, nullable=False)
    indicator_type = Column(String(50), nullable=False)  # domain, url, ip, hash
    threat_type = Column(String(100))  # phishing, malware, c2, spam
    severity = Column(String(20), default=ThreatSeverity.MEDIUM.value)
    source = Column(String(255))
    description = Column(Text)
    tags = Column(JSON)
    first_seen = Column(DateTime(timezone=True))
    last_seen = Column(DateTime(timezone=True))
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    def __repr__(self):
        return f"<ThreatIntel {self.indicator}>"


class NetworkConnection(Base):
    __tablename__ = "network_connections"

    id = Column(Integer, primary_key=True, index=True)
    source_ip = Column(String(45), nullable=False)
    destination_ip = Column(String(45))
    destination_domain = Column(String(255))
    destination_port = Column(Integer)
    protocol = Column(String(20))  # TCP, UDP, HTTPS, HTTP
    bytes_sent = Column(Integer, default=0)
    bytes_received = Column(Integer, default=0)
    packets_sent = Column(Integer, default=0)
    packets_received = Column(Integer, default=0)
    connection_status = Column(String(50))  # established, closed, blocked
    is_blocked = Column(Boolean, default=False)
    block_reason = Column(Text)
    country = Column(String(100))
    asn = Column(String(100))
    threat_score = Column(Float, default=0.0)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

    def __repr__(self):
        return f"<NetworkConnection {self.source_ip} -> {self.destination_ip}>"


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text)
    severity = Column(String(20), default=ThreatSeverity.MEDIUM.value)
    alert_type = Column(String(100))  # phishing, malware, anomaly, policy_violation
    source = Column(String(255))  # URL scan, network monitor, rule engine
    is_read = Column(Boolean, default=False)
    is_acknowledged = Column(Boolean, default=False)
    acknowledged_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    acknowledged_at = Column(DateTime(timezone=True))
    metadata = Column(JSON)

    # Relations
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    user = relationship("User", back_populates="alerts", foreign_keys=[user_id])
    url_scan_id = Column(Integer, ForeignKey("url_scans.id"), nullable=True)
    network_connection_id = Column(Integer, ForeignKey("network_connections.id"), nullable=True)

    # Timestamps
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    def __repr__(self):
        return f"<Alert {self.title} - {self.severity}>"


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    action = Column(String(100), nullable=False)
    resource_type = Column(String(100))
    resource_id = Column(Integer)
    details = Column(JSON)
    ip_address = Column(String(45))
    user_agent = Column(Text)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

    def __repr__(self):
        return f"<AuditLog {self.action}>"
