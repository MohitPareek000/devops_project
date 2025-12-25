import re
import math
import tldextract
from urllib.parse import urlparse, unquote
from typing import Dict, List, Any, Tuple
from collections import Counter


class URLAnalyzer:
    """Extracts features from URLs for phishing detection."""

    SUSPICIOUS_TLDS = [
        'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'club', 'online',
        'site', 'website', 'space', 'pw', 'cc', 'ws', 'info', 'biz'
    ]

    SUSPICIOUS_KEYWORDS = [
        'login', 'signin', 'sign-in', 'log-in', 'account', 'verify',
        'verification', 'update', 'confirm', 'secure', 'security',
        'banking', 'bank', 'paypal', 'ebay', 'amazon', 'apple',
        'microsoft', 'google', 'facebook', 'instagram', 'netflix',
        'password', 'credential', 'authenticate', 'wallet', 'crypto',
        'bitcoin', 'suspended', 'unusual', 'activity', 'locked',
        'unlock', 'restore', 'recover', 'urgent', 'immediately',
        'expire', 'limited', 'free', 'winner', 'prize', 'congratulation'
    ]

    URL_SHORTENERS = [
        'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
        'buff.ly', 'adf.ly', 'bit.do', 'mcaf.ee', 'su.pr', 'tiny.cc',
        'shorte.st', 'cutt.ly', 'rebrand.ly', 'shorturl.at'
    ]

    def __init__(self):
        self.ip_pattern = re.compile(
            r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        )

    def extract_features(self, url: str) -> Dict[str, Any]:
        """Extract all features from a URL."""
        try:
            # Decode URL
            decoded_url = unquote(url)

            # Parse URL
            parsed = urlparse(decoded_url if decoded_url.startswith('http') else f'http://{decoded_url}')
            extracted = tldextract.extract(decoded_url)

            domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain
            subdomain = extracted.subdomain

            # Basic features
            features = {
                'url_length': len(decoded_url),
                'domain_length': len(domain) if domain else 0,
                'subdomain_length': len(subdomain) if subdomain else 0,
                'path_length': len(parsed.path),
                'query_length': len(parsed.query),

                # Character counts
                'num_dots': decoded_url.count('.'),
                'num_hyphens': decoded_url.count('-'),
                'num_underscores': decoded_url.count('_'),
                'num_slashes': decoded_url.count('/'),
                'num_at_symbols': decoded_url.count('@'),
                'num_ampersands': decoded_url.count('&'),
                'num_equals': decoded_url.count('='),
                'num_digits': sum(c.isdigit() for c in decoded_url),
                'num_special_chars': sum(not c.isalnum() and c not in './-_' for c in decoded_url),

                # Boolean features
                'has_ip': self._has_ip_address(domain),
                'has_https': parsed.scheme == 'https',
                'has_port': bool(parsed.port),
                'has_at_symbol': '@' in decoded_url,
                'has_double_slash_redirect': '//' in parsed.path,

                # Calculated features
                'entropy': self._calculate_entropy(decoded_url),
                'digit_ratio': sum(c.isdigit() for c in decoded_url) / max(len(decoded_url), 1),
                'letter_ratio': sum(c.isalpha() for c in decoded_url) / max(len(decoded_url), 1),

                # Domain features
                'tld': extracted.suffix,
                'suspicious_tld': extracted.suffix.lower() in self.SUSPICIOUS_TLDS,
                'subdomain_count': len(subdomain.split('.')) if subdomain else 0,

                # Suspicious patterns
                'suspicious_keywords': self._find_suspicious_keywords(decoded_url),
                'num_suspicious_keywords': len(self._find_suspicious_keywords(decoded_url)),
                'is_shortened': self._is_shortened_url(domain),

                # Advanced features
                'has_brand_in_subdomain': self._has_brand_in_subdomain(subdomain),
                'excessive_subdomains': len(subdomain.split('.')) > 3 if subdomain else False,
                'long_domain': len(domain) > 25 if domain else False,

                # Raw data for reference
                'domain': domain,
                'subdomain': subdomain,
                'path': parsed.path,
                'query': parsed.query
            }

            return features

        except Exception as e:
            # Return minimal features on error
            return {
                'url_length': len(url),
                'domain_length': 0,
                'error': str(e),
                'has_https': url.startswith('https'),
                'entropy': self._calculate_entropy(url),
                'suspicious_keywords': [],
                'num_suspicious_keywords': 0
            }

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0

        counter = Counter(text)
        length = len(text)
        entropy = 0.0

        for count in counter.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return round(entropy, 4)

    def _has_ip_address(self, domain: str) -> bool:
        """Check if domain is an IP address."""
        if not domain:
            return False
        return bool(self.ip_pattern.match(domain))

    def _find_suspicious_keywords(self, url: str) -> List[str]:
        """Find suspicious keywords in URL."""
        url_lower = url.lower()
        found = []
        for keyword in self.SUSPICIOUS_KEYWORDS:
            if keyword in url_lower:
                found.append(keyword)
        return found

    def _is_shortened_url(self, domain: str) -> bool:
        """Check if URL uses a shortener service."""
        if not domain:
            return False
        domain_lower = domain.lower()
        return any(shortener in domain_lower for shortener in self.URL_SHORTENERS)

    def _has_brand_in_subdomain(self, subdomain: str) -> bool:
        """Check if a major brand name is in the subdomain (typosquatting indicator)."""
        if not subdomain:
            return False
        brands = ['google', 'facebook', 'apple', 'microsoft', 'amazon',
                  'paypal', 'netflix', 'instagram', 'twitter', 'linkedin']
        subdomain_lower = subdomain.lower()
        return any(brand in subdomain_lower for brand in brands)

    def get_feature_vector(self, url: str) -> Tuple[List[float], Dict[str, Any]]:
        """Get numerical feature vector for ML model."""
        features = self.extract_features(url)

        # Create numerical feature vector
        vector = [
            features.get('url_length', 0),
            features.get('domain_length', 0),
            features.get('subdomain_length', 0),
            features.get('path_length', 0),
            features.get('query_length', 0),
            features.get('num_dots', 0),
            features.get('num_hyphens', 0),
            features.get('num_underscores', 0),
            features.get('num_slashes', 0),
            features.get('num_at_symbols', 0),
            features.get('num_digits', 0),
            features.get('num_special_chars', 0),
            1 if features.get('has_ip', False) else 0,
            1 if features.get('has_https', False) else 0,
            1 if features.get('has_port', False) else 0,
            1 if features.get('has_at_symbol', False) else 0,
            features.get('entropy', 0),
            features.get('digit_ratio', 0),
            features.get('letter_ratio', 0),
            1 if features.get('suspicious_tld', False) else 0,
            features.get('subdomain_count', 0),
            features.get('num_suspicious_keywords', 0),
            1 if features.get('is_shortened', False) else 0,
            1 if features.get('has_brand_in_subdomain', False) else 0,
            1 if features.get('excessive_subdomains', False) else 0,
            1 if features.get('long_domain', False) else 0,
        ]

        return vector, features


# Singleton instance
url_analyzer = URLAnalyzer()
