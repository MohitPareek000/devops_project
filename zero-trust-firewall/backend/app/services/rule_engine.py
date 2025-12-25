import re
from typing import Dict, List, Tuple, Any
from urllib.parse import urlparse
import tldextract


class PhishingRule:
    """Base class for phishing detection rules."""

    def __init__(self, name: str, weight: float = 1.0, severity: str = "medium"):
        self.name = name
        self.weight = weight
        self.severity = severity

    def check(self, url: str, features: Dict[str, Any]) -> Tuple[bool, float, str]:
        """Check if rule matches. Returns (matched, score, reason)."""
        raise NotImplementedError


class IPAddressRule(PhishingRule):
    """Detect URLs using IP addresses instead of domain names."""

    def __init__(self):
        super().__init__("IP Address in URL", weight=0.8, severity="high")

    def check(self, url: str, features: Dict[str, Any]) -> Tuple[bool, float, str]:
        if features.get('has_ip', False):
            return True, self.weight, "URL contains IP address instead of domain"
        return False, 0, ""


class SuspiciousTLDRule(PhishingRule):
    """Detect suspicious top-level domains."""

    def __init__(self):
        super().__init__("Suspicious TLD", weight=0.4, severity="medium")

    def check(self, url: str, features: Dict[str, Any]) -> Tuple[bool, float, str]:
        if features.get('suspicious_tld', False):
            tld = features.get('tld', '')
            return True, self.weight, f"Suspicious TLD detected: .{tld}"
        return False, 0, ""


class LongURLRule(PhishingRule):
    """Detect abnormally long URLs."""

    def __init__(self):
        super().__init__("Abnormally Long URL", weight=0.3, severity="low")
        self.threshold = 100

    def check(self, url: str, features: Dict[str, Any]) -> Tuple[bool, float, str]:
        url_length = features.get('url_length', 0)
        if url_length > self.threshold:
            return True, self.weight, f"URL length ({url_length}) exceeds threshold ({self.threshold})"
        return False, 0, ""


class SuspiciousKeywordsRule(PhishingRule):
    """Detect phishing-related keywords in URL."""

    def __init__(self):
        super().__init__("Suspicious Keywords", weight=0.5, severity="medium")

    def check(self, url: str, features: Dict[str, Any]) -> Tuple[bool, float, str]:
        keywords = features.get('suspicious_keywords', [])
        if len(keywords) >= 2:
            return True, self.weight, f"Multiple suspicious keywords found: {', '.join(keywords[:5])}"
        elif len(keywords) == 1:
            return True, self.weight * 0.5, f"Suspicious keyword found: {keywords[0]}"
        return False, 0, ""


class URLShortenerRule(PhishingRule):
    """Detect URL shortening services."""

    def __init__(self):
        super().__init__("URL Shortener", weight=0.3, severity="low")

    def check(self, url: str, features: Dict[str, Any]) -> Tuple[bool, float, str]:
        if features.get('is_shortened', False):
            return True, self.weight, "URL uses shortening service"
        return False, 0, ""


class AtSymbolRule(PhishingRule):
    """Detect @ symbol in URL (can be used to hide real destination)."""

    def __init__(self):
        super().__init__("At Symbol in URL", weight=0.7, severity="high")

    def check(self, url: str, features: Dict[str, Any]) -> Tuple[bool, float, str]:
        if features.get('has_at_symbol', False):
            return True, self.weight, "URL contains @ symbol which may hide real destination"
        return False, 0, ""


class ExcessiveSubdomainsRule(PhishingRule):
    """Detect excessive number of subdomains."""

    def __init__(self):
        super().__init__("Excessive Subdomains", weight=0.5, severity="medium")

    def check(self, url: str, features: Dict[str, Any]) -> Tuple[bool, float, str]:
        if features.get('excessive_subdomains', False):
            count = features.get('subdomain_count', 0)
            return True, self.weight, f"Excessive subdomains detected ({count})"
        return False, 0, ""


class BrandInSubdomainRule(PhishingRule):
    """Detect brand names in subdomain (typosquatting)."""

    def __init__(self):
        super().__init__("Brand in Subdomain", weight=0.8, severity="high")

    def check(self, url: str, features: Dict[str, Any]) -> Tuple[bool, float, str]:
        if features.get('has_brand_in_subdomain', False):
            subdomain = features.get('subdomain', '')
            return True, self.weight, f"Brand name detected in subdomain: {subdomain}"
        return False, 0, ""


class HighEntropyRule(PhishingRule):
    """Detect high entropy (randomness) in URL."""

    def __init__(self):
        super().__init__("High Entropy URL", weight=0.4, severity="medium")
        self.threshold = 4.5

    def check(self, url: str, features: Dict[str, Any]) -> Tuple[bool, float, str]:
        entropy = features.get('entropy', 0)
        if entropy > self.threshold:
            return True, self.weight, f"High entropy ({entropy:.2f}) suggests random/obfuscated URL"
        return False, 0, ""


class NoHTTPSRule(PhishingRule):
    """Detect missing HTTPS on sensitive-looking pages."""

    def __init__(self):
        super().__init__("Missing HTTPS", weight=0.3, severity="low")

    def check(self, url: str, features: Dict[str, Any]) -> Tuple[bool, float, str]:
        if not features.get('has_https', False):
            keywords = features.get('suspicious_keywords', [])
            sensitive = ['login', 'signin', 'password', 'account', 'banking', 'payment']
            if any(k in sensitive for k in keywords):
                return True, self.weight, "Sensitive page without HTTPS encryption"
        return False, 0, ""


class DoubleSlashRedirectRule(PhishingRule):
    """Detect double slash in path (potential redirect)."""

    def __init__(self):
        super().__init__("Double Slash Redirect", weight=0.6, severity="medium")

    def check(self, url: str, features: Dict[str, Any]) -> Tuple[bool, float, str]:
        if features.get('has_double_slash_redirect', False):
            return True, self.weight, "Double slash in path may indicate redirect"
        return False, 0, ""


class HomographAttackRule(PhishingRule):
    """Detect potential homograph (lookalike character) attacks."""

    def __init__(self):
        super().__init__("Potential Homograph Attack", weight=0.9, severity="critical")
        self.homograph_chars = {
            'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y',
            'х': 'x', 'ѕ': 's', 'і': 'i', 'ј': 'j', 'ԁ': 'd', 'ɡ': 'g',
            'ɑ': 'a', 'ο': 'o', 'ν': 'v', 'ω': 'w', 'τ': 't'
        }

    def check(self, url: str, features: Dict[str, Any]) -> Tuple[bool, float, str]:
        domain = features.get('domain', '')
        for char in domain:
            if char in self.homograph_chars:
                return True, self.weight, f"Potential homograph attack: '{char}' looks like '{self.homograph_chars[char]}'"
        return False, 0, ""


class RuleEngine:
    """Engine to run all phishing detection rules."""

    def __init__(self):
        self.rules: List[PhishingRule] = [
            IPAddressRule(),
            SuspiciousTLDRule(),
            LongURLRule(),
            SuspiciousKeywordsRule(),
            URLShortenerRule(),
            AtSymbolRule(),
            ExcessiveSubdomainsRule(),
            BrandInSubdomainRule(),
            HighEntropyRule(),
            NoHTTPSRule(),
            DoubleSlashRedirectRule(),
            HomographAttackRule(),
        ]

    def analyze(self, url: str, features: Dict[str, Any]) -> Dict[str, Any]:
        """Run all rules and return analysis results."""
        matched_rules = []
        total_score = 0.0
        max_severity = "info"
        severity_order = ["info", "low", "medium", "high", "critical"]

        for rule in self.rules:
            matched, score, reason = rule.check(url, features)
            if matched:
                matched_rules.append({
                    'name': rule.name,
                    'score': score,
                    'severity': rule.severity,
                    'reason': reason
                })
                total_score += score

                # Track highest severity
                if severity_order.index(rule.severity) > severity_order.index(max_severity):
                    max_severity = rule.severity

        # Normalize score to 0-1 range
        max_possible_score = sum(rule.weight for rule in self.rules)
        normalized_score = min(total_score / max_possible_score, 1.0) if max_possible_score > 0 else 0

        return {
            'matched_rules': matched_rules,
            'rule_score': round(normalized_score, 4),
            'rules_matched_count': len(matched_rules),
            'severity': max_severity if matched_rules else "info",
            'total_rules_checked': len(self.rules)
        }

    def add_rule(self, rule: PhishingRule):
        """Add a custom rule to the engine."""
        self.rules.append(rule)

    def remove_rule(self, rule_name: str):
        """Remove a rule by name."""
        self.rules = [r for r in self.rules if r.name != rule_name]


# Singleton instance
rule_engine = RuleEngine()
