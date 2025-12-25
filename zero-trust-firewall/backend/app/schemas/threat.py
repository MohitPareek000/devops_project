from pydantic import BaseModel, Field, HttpUrl
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class ThreatSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ThreatStatus(str, Enum):
    ACTIVE = "active"
    BLOCKED = "blocked"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


# URL Scan Schemas
class URLScanRequest(BaseModel):
    url: str = Field(..., min_length=1)


class URLScanBatchRequest(BaseModel):
    urls: List[str] = Field(..., min_items=1, max_items=100)


class MatchedRule(BaseModel):
    name: str
    score: float
    severity: str
    reason: str


class URLFeatures(BaseModel):
    url_length: int
    domain_length: int
    path_length: int
    num_dots: int
    num_hyphens: int
    num_underscores: int
    num_digits: int
    num_special_chars: int
    has_ip: bool
    has_https: bool
    has_port: bool
    entropy: float
    suspicious_tld: bool
    suspicious_keywords: List[str]
    is_shortened: bool


class URLScanResponse(BaseModel):
    id: int
    url: str
    domain: Optional[str]
    is_phishing: bool
    confidence_score: float
    ml_score: float
    rule_score: float
    severity: str
    status: str
    features: Optional[Dict[str, Any]]
    matched_rules: Optional[List[Any]]  # Can be MatchedRule dict or legacy string
    scanned_at: datetime

    class Config:
        from_attributes = True


class URLScanListResponse(BaseModel):
    items: List[URLScanResponse]
    total: int
    page: int
    page_size: int
    pages: int


# Threat Intel Schemas
class ThreatIntelCreate(BaseModel):
    indicator: str
    indicator_type: str
    threat_type: Optional[str] = None
    severity: ThreatSeverity = ThreatSeverity.MEDIUM
    source: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[List[str]] = None


class ThreatIntelResponse(BaseModel):
    id: int
    indicator: str
    indicator_type: str
    threat_type: Optional[str]
    severity: str
    source: Optional[str]
    description: Optional[str]
    tags: Optional[List[str]]
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


# Network Connection Schemas
class NetworkConnectionResponse(BaseModel):
    id: int
    source_ip: str
    destination_ip: Optional[str]
    destination_domain: Optional[str]
    destination_port: Optional[int]
    protocol: Optional[str]
    bytes_sent: int
    bytes_received: int
    connection_status: Optional[str]
    is_blocked: bool
    block_reason: Optional[str]
    country: Optional[str]
    threat_score: float
    timestamp: datetime

    class Config:
        from_attributes = True


class NetworkStatsResponse(BaseModel):
    total_connections: int
    blocked_connections: int
    total_bytes_sent: int
    total_bytes_received: int
    top_destinations: List[Dict[str, Any]]
    protocol_distribution: Dict[str, int]
    threat_distribution: Dict[str, int]


# Alert Schemas
class AlertCreate(BaseModel):
    title: str
    description: Optional[str] = None
    severity: ThreatSeverity = ThreatSeverity.MEDIUM
    alert_type: str
    source: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None


class AlertResponse(BaseModel):
    id: int
    title: str
    description: Optional[str]
    severity: str
    alert_type: str
    source: Optional[str]
    is_read: bool
    is_acknowledged: bool
    acknowledged_at: Optional[datetime]
    metadata: Optional[Dict[str, Any]] = Field(default=None, alias="alert_metadata")
    created_at: datetime

    class Config:
        from_attributes = True
        populate_by_name = True


class AlertUpdate(BaseModel):
    is_read: Optional[bool] = None
    is_acknowledged: Optional[bool] = None


# Dashboard Schemas
class DashboardStats(BaseModel):
    total_scans: int
    phishing_detected: int
    blocked_threats: int
    active_alerts: int
    scan_rate: float
    detection_rate: float


class ThreatTrend(BaseModel):
    date: str
    total: int
    phishing: int
    blocked: int


class DashboardResponse(BaseModel):
    stats: DashboardStats
    severity_distribution: Dict[str, int]
    recent_threats: List[URLScanResponse]
    threat_trends: List[ThreatTrend]
    top_blocked_domains: List[Dict[str, Any]]
