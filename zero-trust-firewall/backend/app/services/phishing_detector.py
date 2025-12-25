from typing import Dict, Any, Optional
from datetime import datetime
from sqlalchemy.orm import Session
import tldextract

from .url_analyzer import url_analyzer
from .ml_detector import ml_detector
from .bert_detector import bert_detector
from .threat_intel import threat_intel
from app.models.threat import URLScan, ThreatSeverity, ThreatStatus, Alert
from app.core.config import settings


class PhishingDetector:
    """Main phishing detection orchestrator combining BERT and ML detection."""

    def __init__(self):
        # Hybrid weights: 50% BERT + 50% RandomForest ML
        self.bert_weight = 0.50  # Deep learning score
        self.ml_weight = 0.50   # Traditional ML score

    def analyze_url(
        self,
        url: str,
        db: Optional[Session] = None,
        user_id: Optional[int] = None,
        source_ip: Optional[str] = None,
        user_agent: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Comprehensive URL analysis combining all detection methods.
        """
        # Extract domain
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain

        # Check threat intelligence first
        intel_result = threat_intel.check_domain(domain)

        # If whitelisted, return safe
        if intel_result['is_whitelisted']:
            result = self._create_result(
                url=url,
                domain=domain,
                is_phishing=False,
                confidence_score=0.0,
                ml_score=0.0,
                bert_score=0.0,
                severity='info',
                status='active',
                features={},
                verdict='safe',
                reason='Domain is whitelisted'
            )
            if db:
                self._save_scan(db, result, user_id, source_ip, user_agent)
            return result

        # If blacklisted, return malicious
        if intel_result['is_blacklisted']:
            result = self._create_result(
                url=url,
                domain=domain,
                is_phishing=True,
                confidence_score=1.0,
                ml_score=1.0,
                bert_score=1.0,
                severity='critical',
                status='blocked',
                features={},
                verdict='malicious',
                reason='Domain found in threat intelligence blacklist'
            )
            if db:
                scan = self._save_scan(db, result, user_id, source_ip, user_agent)
                self._create_alert(db, scan, result, user_id)
            return result

        # Extract features
        feature_vector, features = url_analyzer.get_feature_vector(url)

        # Run detection methods: BERT + ML (no rule-based)
        ml_result = ml_detector.predict(url)
        bert_result = bert_detector.predict(url)

        # Hybrid scoring: 50% BERT + 50% ML
        combined_score = (
            bert_result['combined_score'] * self.bert_weight +
            ml_result['ml_score'] * self.ml_weight
        )

        # Determine if phishing based on threshold
        is_phishing = combined_score >= 0.5

        # Determine severity based on score
        if combined_score >= 0.8:
            severity = 'critical'
        elif combined_score >= 0.6:
            severity = 'high'
        elif combined_score >= 0.4:
            severity = 'medium'
        elif combined_score >= 0.2:
            severity = 'low'
        else:
            severity = 'info'

        # Determine status
        status = 'blocked' if is_phishing else 'active'

        # Create verdict
        if is_phishing:
            verdict = 'malicious'
            if combined_score >= 0.8:
                reason = 'High confidence phishing detection'
            else:
                reason = 'Potential phishing detected'
        else:
            verdict = 'safe' if combined_score < 0.2 else 'suspicious'
            reason = 'No significant threats detected' if verdict == 'safe' else 'Some suspicious indicators found'

        # Build result
        result = self._create_result(
            url=url,
            domain=domain,
            is_phishing=is_phishing,
            confidence_score=combined_score,
            ml_score=ml_result['ml_score'],
            bert_score=bert_result['combined_score'],
            severity=severity,
            status=status,
            features=features,
            verdict=verdict,
            reason=reason,
            ml_details=ml_result,
            bert_details=bert_result
        )

        # Save to database
        if db:
            scan = self._save_scan(db, result, user_id, source_ip, user_agent)
            result['scan_id'] = scan.id

            # Create alert for high-severity threats
            if severity in ['critical', 'high']:
                self._create_alert(db, scan, result, user_id)

        return result

    def _create_result(
        self,
        url: str,
        domain: str,
        is_phishing: bool,
        confidence_score: float,
        ml_score: float,
        bert_score: float,
        severity: str,
        status: str,
        features: Dict,
        verdict: str,
        reason: str,
        ml_details: Optional[Dict] = None,
        bert_details: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """Create standardized result dictionary."""
        return {
            'url': url,
            'domain': domain,
            'is_phishing': is_phishing,
            'confidence_score': round(confidence_score, 4),
            'ml_score': round(ml_score, 4),
            'bert_score': round(bert_score, 4),
            'severity': severity,
            'status': status,
            'features': features,
            'verdict': verdict,
            'reason': reason,
            'ml_details': ml_details,
            'bert_details': bert_details,
            'detection_weights': {
                'bert': 0.50,
                'ml': 0.50
            },
            'scanned_at': datetime.utcnow().isoformat()
        }

    def _save_scan(
        self,
        db: Session,
        result: Dict,
        user_id: Optional[int],
        source_ip: Optional[str],
        user_agent: Optional[str]
    ) -> URLScan:
        """Save scan result to database."""
        scan = URLScan(
            url=result['url'],
            domain=result['domain'],
            is_phishing=result['is_phishing'],
            confidence_score=result['confidence_score'],
            ml_score=result['ml_score'],
            rule_score=0.0,  # No longer using rule-based detection
            severity=result['severity'],
            status=result['status'],
            features=result['features'],
            matched_rules=[],  # No longer using rule-based detection
            user_id=user_id,
            source_ip=source_ip,
            user_agent=user_agent
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)
        return scan

    def _create_alert(
        self,
        db: Session,
        scan: URLScan,
        result: Dict,
        user_id: Optional[int]
    ):
        """Create alert for detected threat."""
        alert = Alert(
            title=f"Phishing URL Detected: {result['domain']}",
            description=result['reason'],
            severity=result['severity'],
            alert_type='phishing',
            source='URL Scanner',
            url_scan_id=scan.id,
            user_id=user_id,
            alert_metadata={
                'url': result['url'],
                'confidence_score': result['confidence_score'],
                'bert_score': result['bert_score'],
                'ml_score': result['ml_score']
            }
        )
        db.add(alert)
        db.commit()


# Singleton instance
phishing_detector = PhishingDetector()
