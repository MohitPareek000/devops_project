from typing import Dict, Any, Optional
from datetime import datetime
from sqlalchemy.orm import Session
import tldextract

from .url_analyzer import url_analyzer
from .rule_engine import rule_engine
from .ml_detector import ml_detector
from .bert_detector import bert_detector
from .threat_intel import threat_intel
from app.models.threat import URLScan, ThreatSeverity, ThreatStatus, Alert
from app.core.config import settings


class PhishingDetector:
    """Main phishing detection orchestrator combining ML, BERT, rules, and threat intel."""

    def __init__(self):
        # Hybrid weights for combining all detection methods
        # BERT/Deep Learning: Best for semantic understanding and typosquatting
        # RandomForest ML: Good for statistical patterns
        # Rules: Deterministic detection of known patterns
        self.bert_weight = 0.35  # Deep learning score
        self.ml_weight = 0.25   # Traditional ML score
        self.rule_weight = 0.40  # Rule-based score (highest for reliability)

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
                rule_score=0.0,
                severity='info',
                status='active',
                features={},
                matched_rules=[],
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
                rule_score=1.0,
                bert_score=1.0,
                severity='critical',
                status='blocked',
                features={},
                matched_rules=[{'name': 'Blacklist Match', 'severity': 'critical'}],
                verdict='malicious',
                reason='Domain found in threat intelligence blacklist'
            )
            if db:
                scan = self._save_scan(db, result, user_id, source_ip, user_agent)
                self._create_alert(db, scan, result, user_id)
            return result

        # Extract features
        feature_vector, features = url_analyzer.get_feature_vector(url)

        # Run all detection methods
        ml_result = ml_detector.predict(url)
        bert_result = bert_detector.predict(url)
        rule_result = rule_engine.analyze(url, features)

        # Hybrid scoring: Combine all three methods
        combined_score = (
            bert_result['combined_score'] * self.bert_weight +
            ml_result['ml_score'] * self.ml_weight +
            rule_result['rule_score'] * self.rule_weight
        )

        # Check for critical-severity rules that should override the normal scoring
        # Critical rules like typosquatting should automatically flag as phishing
        critical_rules_matched = [
            r for r in rule_result.get('matched_rules', [])
            if r.get('severity') == 'critical'
        ]

        # Check for high-severity rules that should boost the score
        high_severity_rules = [
            r for r in rule_result.get('matched_rules', [])
            if r.get('severity') == 'high'
        ]

        # If any critical rule matched, override the score and mark as phishing
        if critical_rules_matched:
            # Critical rules = definite phishing
            combined_score = max(combined_score, 0.85)
            is_phishing = True
        elif high_severity_rules and len(high_severity_rules) >= 2:
            # Multiple high-severity rules = likely phishing
            combined_score = max(combined_score, 0.65)
            is_phishing = True
        elif high_severity_rules:
            # Single high-severity rule = boost score but use threshold
            combined_score = max(combined_score, 0.55)
            is_phishing = combined_score >= 0.45
        else:
            # Determine if phishing based on normal threshold (lowered for better catch rate)
            is_phishing = combined_score >= 0.45

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
            rule_score=rule_result['rule_score'],
            severity=severity,
            status=status,
            features=features,
            matched_rules=rule_result['matched_rules'],  # Pass full rule objects
            verdict=verdict,
            reason=reason,
            ml_details=ml_result,
            rule_details=rule_result
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
        rule_score: float,
        severity: str,
        status: str,
        features: Dict,
        matched_rules: list,
        verdict: str,
        reason: str,
        ml_details: Optional[Dict] = None,
        rule_details: Optional[Dict] = None
    ) -> Dict[str, Any]:
        """Create standardized result dictionary."""
        return {
            'url': url,
            'domain': domain,
            'is_phishing': is_phishing,
            'confidence_score': round(confidence_score, 4),
            'ml_score': round(ml_score, 4),
            'rule_score': round(rule_score, 4),
            'severity': severity,
            'status': status,
            'features': features,
            'matched_rules': matched_rules,
            'verdict': verdict,
            'reason': reason,
            'ml_details': ml_details,
            'rule_details': rule_details,
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
            rule_score=result['rule_score'],
            severity=result['severity'],
            status=result['status'],
            features=result['features'],
            matched_rules=result['matched_rules'],
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
                'matched_rules': result['matched_rules']
            }
        )
        db.add(alert)
        db.commit()


# Singleton instance
phishing_detector = PhishingDetector()
