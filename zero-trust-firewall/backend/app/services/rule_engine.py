import re
from typing import Dict, List, Tuple, Any
from urllib.parse import urlparse
import tldextract


# Known legitimate domains that should never trigger rules
KNOWN_LEGITIMATE_DOMAINS = {
    'google.com', 'www.google.com', 'mail.google.com', 'drive.google.com', 'docs.google.com',
    'amazon.com', 'www.amazon.com', 'aws.amazon.com',
    'microsoft.com', 'www.microsoft.com', 'login.microsoftonline.com', 'outlook.live.com',
    'apple.com', 'www.apple.com', 'icloud.com',
    'facebook.com', 'www.facebook.com', 'm.facebook.com',
    'twitter.com', 'www.twitter.com', 'x.com',
    'linkedin.com', 'www.linkedin.com',
    'github.com', 'www.github.com',
    'netflix.com', 'www.netflix.com',
    'youtube.com', 'www.youtube.com',
    'instagram.com', 'www.instagram.com',
    'paypal.com', 'www.paypal.com',
    'ebay.com', 'www.ebay.com',
    'chase.com', 'www.chase.com', 'secure.chase.com',
    'bankofamerica.com', 'www.bankofamerica.com',
    'wellsfargo.com', 'www.wellsfargo.com',
    'reddit.com', 'www.reddit.com',
    'wikipedia.org', 'www.wikipedia.org', 'en.wikipedia.org',
    'stackoverflow.com', 'www.stackoverflow.com',
    'dropbox.com', 'www.dropbox.com',
    'spotify.com', 'www.spotify.com',
    'zoom.us', 'www.zoom.us',
    'slack.com', 'www.slack.com',
    'notion.so', 'www.notion.so',
    'figma.com', 'www.figma.com',
    'portal.azure.com', 'cloud.google.com',
    'outlook.com', 'office.com', 'office365.com',
    'yahoo.com', 'mail.yahoo.com',
    'cnn.com', 'www.cnn.com',
    'bbc.com', 'www.bbc.com', 'bbc.co.uk',
    'nytimes.com', 'www.nytimes.com',
    'walmart.com', 'www.walmart.com',
    'target.com', 'www.target.com',
    'bestbuy.com', 'www.bestbuy.com',
    'etsy.com', 'www.etsy.com',
    'venmo.com', 'www.venmo.com',
    'stripe.com', 'www.stripe.com',
    'twitch.tv', 'www.twitch.tv',
    'discord.com', 'www.discord.com',
    'steam.com', 'store.steampowered.com', 'steampowered.com',
    'coinbase.com', 'www.coinbase.com',
    'binance.com', 'www.binance.com',
}


def is_known_legitimate_domain(url: str, features: Dict[str, Any]) -> bool:
    """Check if the URL belongs to a known legitimate domain."""
    try:
        domain = features.get('domain', '').lower()
        subdomain = features.get('subdomain', '').lower()
        full_domain = f"{subdomain}.{domain}" if subdomain else domain

        # Check both the full domain and the registered domain
        if domain in KNOWN_LEGITIMATE_DOMAINS:
            return True
        if full_domain in KNOWN_LEGITIMATE_DOMAINS:
            return True

        # Also check without www prefix
        if domain.startswith('www.'):
            base_domain = domain[4:]
            if base_domain in KNOWN_LEGITIMATE_DOMAINS:
                return True

        return False
    except Exception:
        return False


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
        super().__init__("Abnormally Long URL", weight=0.2, severity="low")
        self.threshold = 150  # Increased threshold to reduce false positives

    def check(self, url: str, features: Dict[str, Any]) -> Tuple[bool, float, str]:
        url_length = features.get('url_length', 0)
        # Many legitimate URLs can be long (e.g., Google search, tracking params)
        if url_length > self.threshold:
            # Only flag if also has other suspicious indicators
            if features.get('suspicious_tld', False) or features.get('has_ip', False):
                return True, self.weight, f"URL length ({url_length}) exceeds threshold with suspicious indicators"
        if url_length > 200:  # Very long URLs are more suspicious
            return True, self.weight, f"Very long URL ({url_length} chars)"
        return False, 0, ""


class SuspiciousKeywordsRule(PhishingRule):
    """Detect phishing-related keywords in URL."""

    def __init__(self):
        super().__init__("Suspicious Keywords", weight=0.4, severity="medium")
        # Keywords that are suspicious only in certain contexts
        self.high_risk_keywords = ['verify', 'suspend', 'confirm', 'unlock', 'unusual', 'limited']

    def check(self, url: str, features: Dict[str, Any]) -> Tuple[bool, float, str]:
        keywords = features.get('suspicious_keywords', [])

        # Filter out common words that appear in legitimate URLs
        # "login", "account", "secure" are often in legitimate banking/service URLs
        high_risk_found = [k for k in keywords if k in self.high_risk_keywords]

        if len(high_risk_found) >= 2:
            return True, self.weight, f"Multiple high-risk keywords found: {', '.join(high_risk_found[:5])}"
        elif len(keywords) >= 3:
            return True, self.weight * 0.7, f"Multiple suspicious keywords found: {', '.join(keywords[:5])}"
        elif len(high_risk_found) == 1:
            return True, self.weight * 0.5, f"High-risk keyword found: {high_risk_found[0]}"
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
        super().__init__("High Entropy URL", weight=0.35, severity="medium")
        self.threshold = 4.8  # Increased threshold - many legitimate URLs have high entropy

    def check(self, url: str, features: Dict[str, Any]) -> Tuple[bool, float, str]:
        entropy = features.get('entropy', 0)
        url_length = features.get('url_length', 0)

        # High entropy is only suspicious for shorter domains (long URLs naturally have higher entropy)
        if entropy > self.threshold and url_length < 80:
            return True, self.weight, f"High entropy ({entropy:.2f}) suggests random/obfuscated URL"
        # Very high entropy is always suspicious
        if entropy > 5.2:
            return True, self.weight * 0.8, f"Very high entropy ({entropy:.2f}) in URL"
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


class MissingHTTPSWithSensitiveKeywordsRule(PhishingRule):
    """Detect HTTP (not HTTPS) on pages with sensitive keywords."""

    def __init__(self):
        super().__init__("Missing HTTPS on Sensitive Page", weight=0.7, severity="high")
        self.sensitive_keywords = [
            'login', 'signin', 'password', 'account', 'banking', 'payment',
            'verify', 'secure', 'credential', 'authenticate', 'wallet', 'crypto'
        ]

    def check(self, url: str, features: Dict[str, Any]) -> Tuple[bool, float, str]:
        if not features.get('has_https', True):
            keywords_found = features.get('suspicious_keywords', [])
            sensitive_found = [k for k in keywords_found if k in self.sensitive_keywords]
            if sensitive_found:
                return True, self.weight, f"Sensitive page without HTTPS: contains '{', '.join(sensitive_found[:3])}'"
        return False, 0, ""


class BrandMimicryRule(PhishingRule):
    """Detect brand names combined with suspicious domain patterns."""

    def __init__(self):
        super().__init__("Brand Mimicry", weight=0.85, severity="critical")
        self.brands = [
            'paypal', 'amazon', 'google', 'facebook', 'microsoft', 'apple',
            'netflix', 'instagram', 'twitter', 'linkedin', 'dropbox', 'chase',
            'wellsfargo', 'bankofamerica', 'citibank', 'steam', 'ebay',
            'walmart', 'target', 'bestbuy', 'outlook', 'yahoo', 'dhl',
            'fedex', 'ups', 'usps', 'coinbase', 'binance', 'venmo', 'zelle'
        ]
        self.suspicious_suffixes = [
            '-secure', '-login', '-verify', '-update', '-account', '-support',
            '-help', '-service', '-team', '-alert', '-confirm', '-auth',
            '-billing', '-payment', '-recovery', '-unlock', '-suspended'
        ]

    def check(self, url: str, features: Dict[str, Any]) -> Tuple[bool, float, str]:
        domain = features.get('domain', '').lower()
        subdomain = features.get('subdomain', '').lower()
        full_domain = f"{subdomain}.{domain}" if subdomain else domain

        for brand in self.brands:
            if brand in full_domain:
                # Check if combined with suspicious suffix
                for suffix in self.suspicious_suffixes:
                    if f"{brand}{suffix}" in full_domain or f"{suffix.lstrip('-')}-{brand}" in full_domain:
                        return True, self.weight, f"Brand mimicry: '{brand}' combined with suspicious suffix"
                # Check if brand is in subdomain pointing to different domain
                if brand in subdomain and brand not in domain:
                    return True, self.weight, f"Brand '{brand}' in subdomain pointing to different domain"
        return False, 0, ""


class RandomStringDomainRule(PhishingRule):
    """Detect domains that appear to be randomly generated."""

    def __init__(self):
        super().__init__("Random String Domain", weight=0.6, severity="medium")
        # Consonant clusters that are unusual in real words
        self.unusual_patterns = [
            r'[bcdfghjklmnpqrstvwxz]{4,}',  # 4+ consonants in a row
            r'\d{3,}',  # 3+ digits in a row in domain
            r'[a-z]\d[a-z]\d',  # Alternating letters and digits
        ]

    def check(self, url: str, features: Dict[str, Any]) -> Tuple[bool, float, str]:
        domain = features.get('domain', '').lower().split('.')[0]  # Get domain without TLD

        if len(domain) < 5:
            return False, 0, ""

        for pattern in self.unusual_patterns:
            if re.search(pattern, domain):
                return True, self.weight, f"Domain '{domain}' appears randomly generated"

        # Check entropy of domain name (high entropy = likely random)
        domain_entropy = features.get('entropy', 0)
        if domain_entropy > 4.5 and len(domain) > 10:
            return True, self.weight * 0.8, f"High entropy domain suggests random generation"

        return False, 0, ""


class SuspiciousPathPatternRule(PhishingRule):
    """Detect suspicious patterns in URL path."""

    def __init__(self):
        super().__init__("Suspicious Path Pattern", weight=0.5, severity="medium")
        self.suspicious_paths = [
            r'/\.well-known/',  # Hidden paths
            r'/wp-admin/',  # WordPress admin (often targeted)
            r'/wp-includes/',
            r'/login\.php',
            r'/signin\.php',
            r'/verify\.html',
            r'/account\.html',
            r'/secure/',
            r'/auth/',
            r'/validation/',
            r'/confirmation/',
        ]

    def check(self, url: str, features: Dict[str, Any]) -> Tuple[bool, float, str]:
        path = features.get('path', '').lower()

        for pattern in self.suspicious_paths:
            if re.search(pattern, path):
                return True, self.weight, f"Suspicious path pattern detected"

        # Check for encoded characters in path (obfuscation)
        if '%' in path:
            encoded_count = path.count('%')
            if encoded_count > 3:
                return True, self.weight * 0.7, f"Multiple encoded characters in path ({encoded_count})"

        return False, 0, ""


class MultipleHyphensRule(PhishingRule):
    """Detect excessive hyphens in domain (common in phishing)."""

    def __init__(self):
        super().__init__("Multiple Hyphens in Domain", weight=0.4, severity="medium")

    def check(self, url: str, features: Dict[str, Any]) -> Tuple[bool, float, str]:
        domain = features.get('domain', '')
        subdomain = features.get('subdomain', '')

        # Only check the main domain name, not subdomains (many CDNs use hyphens in subdomains)
        main_domain = domain.split('.')[0] if domain else ''
        hyphen_count = main_domain.count('-')

        if hyphen_count >= 4:
            return True, self.weight, f"Excessive hyphens in domain ({hyphen_count})"
        elif hyphen_count == 3:
            return True, self.weight * 0.6, f"Multiple hyphens in domain may indicate phishing"
        return False, 0, ""


class DataURIRule(PhishingRule):
    """Detect data URI schemes that could be used for phishing."""

    def __init__(self):
        super().__init__("Data URI Scheme", weight=0.9, severity="critical")

    def check(self, url: str, features: Dict[str, Any]) -> Tuple[bool, float, str]:
        url_lower = url.lower()
        if url_lower.startswith('data:') or 'data:text/html' in url_lower:
            return True, self.weight, "Data URI scheme can hide malicious content"
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


class TyposquattingRule(PhishingRule):
    """Detect typosquatting attacks using character substitution."""

    def __init__(self):
        super().__init__("Typosquatting Attack", weight=0.95, severity="critical")
        # Popular brands that are commonly targeted
        self.brands = {
            'paypal': ['paypa1', 'paypa|', 'paypai', 'paypol', 'paypaI', 'paypaal', 'paypall', 'peypal', 'payp4l', 'p4ypal', 'paaypal'],
            'amazon': ['amaz0n', 'amazom', 'arnazon', 'amazn', 'amazonn', 'amzon', 'amazone', 'anazon', 'amazan'],
            'google': ['g00gle', 'googIe', 'gooogle', 'googel', 'go0gle', 'googl3', 'googe', 'goog1e', 'googie'],
            'facebook': ['faceb00k', 'facebok', 'faceboook', 'facebookk', 'faceb0ok', 'faccebook', 'faceebook', 'facbook'],
            'microsoft': ['micros0ft', 'mircosoft', 'microsft', 'microsooft', 'microsof', 'micr0soft', 'mlcrosoft', 'rnicrosoft'],
            'apple': ['app1e', 'appIe', 'applle', 'aple', 'aplle', 'appel', 'appl3'],
            'netflix': ['netf1ix', 'netfIix', 'netfilx', 'netflex', 'nettflix', 'netfl1x', 'n3tflix'],
            'instagram': ['1nstagram', 'instagran', 'instagramm', 'instagarm', 'lnstagram', 'instgram', 'instagrarn'],
            'twitter': ['tw1tter', 'twiter', 'twitterr', 'twltter', 'tvvitter', 'twitt3r'],
            'linkedin': ['linkedln', 'linkdin', 'linkedinn', '1inkedin', 'linkediln', 'linkediin'],
            'dropbox': ['dr0pbox', 'dropb0x', 'drophox', 'droppbox', 'dropboxx'],
            'chase': ['chas3', 'chasse', 'chaze', 'chasee'],
            'wellsfargo': ['we11sfargo', 'wellsfarg0', 'wellsfargoo', 'welsfargo', 'wellsfarqo'],
            'bankofamerica': ['bankofamer1ca', 'bankofamerlca', 'bankofamericaa'],
            'citibank': ['c1tibank', 'citlbank', 'citibanck', 'citibannk'],
            'usbank': ['usbannk', 'usbanck', 'u5bank'],
            'steam': ['stearn', 'steaam', 'stean', 'st3am'],
            'ebay': ['ebey', '3bay', 'ebayy', 'ebaay'],
            'walmart': ['wa1mart', 'walmrat', 'wallmart', 'waimart'],
            'target': ['targ3t', 'targett', 'tarqet'],
            'bestbuy': ['bestbuuy', 'b3stbuy', 'besttbuy'],
            'office365': ['0ffice365', 'office356', 'offlce365'],
            'outlook': ['0utlook', 'outlo0k', 'outlookk', 'outIook'],
            'yahoo': ['yah00', 'yahooo', 'yaho0', 'yehoo'],
            'dhl': ['dh1', 'dhll', 'dhi'],
            'fedex': ['f3dex', 'fedx', 'fedxe', 'fed3x'],
            'ups': ['upss', 'u9s', 'uups'],
            'usps': ['uspss', 'u5ps', 'ussp'],
        }
        # Character substitutions commonly used in typosquatting
        self.char_subs = {
            '0': 'o', 'o': '0',
            '1': 'l', 'l': '1', 'I': 'l', 'i': 'l',
            '3': 'e', 'e': '3',
            '4': 'a', 'a': '4',
            '5': 's', 's': '5',
            '|': 'l',
            'rn': 'm', 'vv': 'w',
        }

    def _normalize_domain(self, domain: str) -> str:
        """Normalize domain by replacing common substitution characters."""
        normalized = domain.lower()
        # Replace common character substitutions
        normalized = normalized.replace('0', 'o')
        normalized = normalized.replace('1', 'l')
        normalized = normalized.replace('|', 'l')
        normalized = normalized.replace('3', 'e')
        normalized = normalized.replace('4', 'a')
        normalized = normalized.replace('5', 's')
        normalized = normalized.replace('rn', 'm')
        normalized = normalized.replace('vv', 'w')
        return normalized

    def check(self, url: str, features: Dict[str, Any]) -> Tuple[bool, float, str]:
        domain = features.get('domain', '').lower()
        subdomain = features.get('subdomain', '').lower()
        full_domain = f"{subdomain}.{domain}" if subdomain else domain

        # Check against known typosquatting variants
        for brand, variants in self.brands.items():
            for variant in variants:
                if variant in full_domain:
                    return True, self.weight, f"Typosquatting detected: '{variant}' mimics '{brand}'"

        # Check normalized domain against brand names
        normalized = self._normalize_domain(full_domain)
        for brand in self.brands.keys():
            if brand in normalized and brand not in full_domain:
                return True, self.weight, f"Typosquatting detected: domain normalizes to contain '{brand}'"
            # Check if domain contains brand with added/removed chars
            if brand in full_domain.replace('-', '').replace('.', ''):
                # It's legitimate if it's exactly the brand
                continue

        # Check for brand names with common suffixes/prefixes in suspicious patterns
        suspicious_patterns = [
            r'(paypal|amazon|google|facebook|microsoft|apple|netflix|instagram|twitter|linkedin)[-.]?(secure|login|verify|update|account|support|help|service)',
            r'(secure|login|verify|update|account|support|help|service)[-.]?(paypal|amazon|google|facebook|microsoft|apple|netflix|instagram|twitter|linkedin)',
        ]

        for pattern in suspicious_patterns:
            if re.search(pattern, full_domain):
                match = re.search(pattern, full_domain)
                return True, self.weight * 0.8, f"Suspicious brand + keyword combination in domain: {match.group()}"

        return False, 0, ""


class RuleEngine:
    """Engine to run all phishing detection rules."""

    def __init__(self):
        self.rules: List[PhishingRule] = [
            # Critical severity rules (highest priority)
            TyposquattingRule(),
            HomographAttackRule(),
            BrandMimicryRule(),
            DataURIRule(),
            # High severity rules
            IPAddressRule(),
            AtSymbolRule(),
            BrandInSubdomainRule(),
            MissingHTTPSWithSensitiveKeywordsRule(),
            # Medium severity rules
            SuspiciousTLDRule(),
            SuspiciousKeywordsRule(),
            ExcessiveSubdomainsRule(),
            HighEntropyRule(),
            DoubleSlashRedirectRule(),
            RandomStringDomainRule(),
            SuspiciousPathPatternRule(),
            MultipleHyphensRule(),
            # Low severity rules
            LongURLRule(),
            URLShortenerRule(),
            NoHTTPSRule(),
        ]

    def analyze(self, url: str, features: Dict[str, Any]) -> Dict[str, Any]:
        """Run all rules and return analysis results."""
        matched_rules = []
        total_score = 0.0
        max_severity = "info"
        severity_order = ["info", "low", "medium", "high", "critical"]

        # Check if this is a known legitimate domain - skip most rules if so
        is_legitimate = is_known_legitimate_domain(url, features)

        # Rules that should still run even for legitimate domains (e.g., if URL is compromised)
        always_run_rules = {'Data URI Scheme', 'Potential Homograph Attack'}

        for rule in self.rules:
            # Skip non-critical rules for known legitimate domains
            if is_legitimate and rule.name not in always_run_rules:
                continue

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

        # Calculate rule score based on severity and matched rules
        # Instead of normalizing by ALL rules, use a more intuitive scoring:
        # - Critical rule match = 0.85-1.0
        # - High severity rules = 0.6-0.85
        # - Medium severity = 0.3-0.6
        # - Low severity = 0.1-0.3

        if not matched_rules:
            normalized_score = 0.0
        else:
            # Score based on highest severity matched
            if max_severity == 'critical':
                # Critical rules should give high scores
                base_score = 0.85
                # Add bonus for multiple critical rules
                critical_count = sum(1 for r in matched_rules if r['severity'] == 'critical')
                normalized_score = min(base_score + (critical_count - 1) * 0.05, 1.0)
            elif max_severity == 'high':
                base_score = 0.6
                high_count = sum(1 for r in matched_rules if r['severity'] == 'high')
                normalized_score = min(base_score + (high_count - 1) * 0.1, 0.85)
            elif max_severity == 'medium':
                base_score = 0.3
                medium_count = sum(1 for r in matched_rules if r['severity'] == 'medium')
                normalized_score = min(base_score + (medium_count - 1) * 0.1, 0.6)
            else:  # low
                base_score = 0.1
                low_count = len(matched_rules)
                normalized_score = min(base_score + (low_count - 1) * 0.05, 0.3)

            # Boost score if multiple different severity rules matched
            severity_types = len(set(r['severity'] for r in matched_rules))
            if severity_types >= 2:
                normalized_score = min(normalized_score + 0.1, 1.0)

        return {
            'matched_rules': matched_rules,
            'rule_score': round(normalized_score, 4),
            'rules_matched_count': len(matched_rules),
            'severity': max_severity if matched_rules else "info",
            'total_rules_checked': len(self.rules),
            'is_known_legitimate': is_legitimate
        }

    def add_rule(self, rule: PhishingRule):
        """Add a custom rule to the engine."""
        self.rules.append(rule)

    def remove_rule(self, rule_name: str):
        """Remove a rule by name."""
        self.rules = [r for r in self.rules if r.name != rule_name]


# Singleton instance
rule_engine = RuleEngine()
