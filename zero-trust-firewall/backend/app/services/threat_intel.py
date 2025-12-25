import asyncio
import httpx
from typing import Set, Optional, Dict, Any
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from app.core.config import settings
from app.models.threat import ThreatIntel


class ThreatIntelligenceService:
    """Service for managing threat intelligence data."""

    def __init__(self):
        self.blacklist: Set[str] = set()
        self.whitelist: Set[str] = set()
        self.last_update: Optional[datetime] = None
        self.update_interval = timedelta(hours=24)

        # Known safe domains
        self.default_whitelist = {
            'google.com', 'youtube.com', 'facebook.com', 'twitter.com',
            'instagram.com', 'linkedin.com', 'github.com', 'microsoft.com',
            'apple.com', 'amazon.com', 'netflix.com', 'reddit.com',
            'wikipedia.org', 'stackoverflow.com', 'cloudflare.com',
            'googleapis.com', 'gstatic.com', 'googleusercontent.com'
        }
        self.whitelist.update(self.default_whitelist)

    async def update_blacklist(self) -> Dict[str, Any]:
        """Update phishing blacklist from external sources."""
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(settings.PHISHING_BLACKLIST_URL)

                if response.status_code == 200:
                    domains = set()
                    for line in response.text.split('\n'):
                        domain = line.strip().lower()
                        if domain and not domain.startswith('#'):
                            domains.add(domain)

                    self.blacklist.update(domains)
                    self.last_update = datetime.utcnow()

                    return {
                        'success': True,
                        'domains_added': len(domains),
                        'total_blacklisted': len(self.blacklist),
                        'updated_at': self.last_update.isoformat()
                    }

        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

        return {'success': False, 'error': 'Unknown error'}

    def is_blacklisted(self, domain: str) -> bool:
        """Check if domain is in blacklist."""
        domain = domain.lower().strip()

        # Check exact match
        if domain in self.blacklist:
            return True

        # Check parent domains
        parts = domain.split('.')
        for i in range(len(parts) - 1):
            parent = '.'.join(parts[i:])
            if parent in self.blacklist:
                return True

        return False

    def is_whitelisted(self, domain: str) -> bool:
        """Check if domain is in whitelist."""
        domain = domain.lower().strip()

        # Check exact match
        if domain in self.whitelist:
            return True

        # Check parent domains
        parts = domain.split('.')
        for i in range(len(parts) - 1):
            parent = '.'.join(parts[i:])
            if parent in self.whitelist:
                return True

        return False

    def add_to_blacklist(self, domain: str):
        """Add domain to blacklist."""
        self.blacklist.add(domain.lower().strip())

    def add_to_whitelist(self, domain: str):
        """Add domain to whitelist."""
        self.whitelist.add(domain.lower().strip())

    def remove_from_blacklist(self, domain: str):
        """Remove domain from blacklist."""
        self.blacklist.discard(domain.lower().strip())

    def remove_from_whitelist(self, domain: str):
        """Remove domain from whitelist."""
        self.whitelist.discard(domain.lower().strip())

    def check_domain(self, domain: str) -> Dict[str, Any]:
        """Check domain against threat intelligence."""
        domain = domain.lower().strip()

        result = {
            'domain': domain,
            'is_blacklisted': False,
            'is_whitelisted': False,
            'threat_level': 'unknown'
        }

        if self.is_whitelisted(domain):
            result['is_whitelisted'] = True
            result['threat_level'] = 'safe'
        elif self.is_blacklisted(domain):
            result['is_blacklisted'] = True
            result['threat_level'] = 'malicious'
        else:
            result['threat_level'] = 'unknown'

        return result

    def get_stats(self) -> Dict[str, Any]:
        """Get threat intelligence statistics."""
        return {
            'blacklist_count': len(self.blacklist),
            'whitelist_count': len(self.whitelist),
            'last_update': self.last_update.isoformat() if self.last_update else None
        }

    async def sync_from_database(self, db: Session):
        """Sync threat intelligence from database."""
        try:
            threats = db.query(ThreatIntel).filter(
                ThreatIntel.is_active == True,
                ThreatIntel.indicator_type.in_(['domain', 'url'])
            ).all()

            for threat in threats:
                if threat.threat_type == 'whitelist':
                    self.whitelist.add(threat.indicator.lower())
                else:
                    self.blacklist.add(threat.indicator.lower())

            return {
                'success': True,
                'synced_count': len(threats)
            }

        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }


# Singleton instance
threat_intel = ThreatIntelligenceService()
