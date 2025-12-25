import re
import math
import tldextract
from urllib.parse import urlparse, unquote
from typing import Dict, List, Any, Tuple, Optional
from collections import Counter


class URLAnalyzer:
    """Extracts features from URLs for phishing detection."""

    # High-risk TLDs commonly used in phishing
    SUSPICIOUS_TLDS = [
        'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'club', 'online',
        'site', 'website', 'space', 'pw', 'cc', 'ws', 'info', 'biz',
        'click', 'link', 'work', 'date', 'download', 'racing', 'review',
        'country', 'stream', 'gdn', 'mom', 'xin', 'kim', 'men', 'loan',
        'win', 'party', 'science', 'webcam', 'trade', 'accountant', 'faith'
    ]

    # Phishing-related keywords with severity
    SUSPICIOUS_KEYWORDS = [
        'login', 'signin', 'sign-in', 'log-in', 'account', 'verify',
        'verification', 'update', 'confirm', 'secure', 'security',
        'banking', 'bank', 'paypal', 'ebay', 'amazon', 'apple',
        'microsoft', 'google', 'facebook', 'instagram', 'netflix',
        'password', 'credential', 'authenticate', 'wallet', 'crypto',
        'bitcoin', 'suspended', 'unusual', 'activity', 'locked',
        'unlock', 'restore', 'recover', 'urgent', 'immediately',
        'expire', 'limited', 'free', 'winner', 'prize', 'congratulation',
        'alert', 'warning', 'blocked', 'disabled', 'validate', 'reactivate',
        'billing', 'invoice', 'payment', 'refund', 'claim', 'reward',
        'notification', 'action-required', 'required', 'helpdesk', 'support'
    ]

    # High-value target brands for typosquatting
    TARGET_BRANDS = [
        'google', 'facebook', 'apple', 'microsoft', 'amazon', 'paypal',
        'netflix', 'instagram', 'twitter', 'linkedin', 'chase', 'wellsfargo',
        'bankofamerica', 'citibank', 'usbank', 'capitalone', 'amex',
        'dropbox', 'icloud', 'outlook', 'hotmail', 'yahoo', 'gmail',
        'whatsapp', 'telegram', 'snapchat', 'tiktok', 'spotify', 'uber',
        'coinbase', 'binance', 'kraken', 'blockchain', 'venmo', 'zelle',
        'steam', 'playstation', 'xbox', 'nintendo', 'twitch', 'discord',
        'adobe', 'salesforce', 'oracle', 'sap', 'docusign', 'stripe'
    ]

    URL_SHORTENERS = [
        'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
        'buff.ly', 'adf.ly', 'bit.do', 'mcaf.ee', 'su.pr', 'tiny.cc',
        'shorte.st', 'cutt.ly', 'rebrand.ly', 'shorturl.at', 'v.gd',
        'rb.gy', 'qr.ae', 'bc.vc', 'j.mp', 'han.gl', 'u.to'
    ]

    # Homograph characters (Cyrillic/Greek that look like Latin)
    HOMOGRAPH_MAP = {
        'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y',
        'х': 'x', 'ѕ': 's', 'і': 'i', 'ј': 'j', 'һ': 'h', 'ԁ': 'd',
        'ո': 'n', 'ս': 'u', 'ν': 'v', 'ω': 'w', 'α': 'a', 'β': 'b',
        'ε': 'e', 'η': 'n', 'ι': 'i', 'κ': 'k', 'μ': 'u', 'ρ': 'p',
        'τ': 't', 'υ': 'u', 'χ': 'x', 'ο': 'o', 'ϲ': 'c', 'ɡ': 'g',
        'ⅰ': 'i', 'ⅱ': 'ii', 'ⅲ': 'iii', 'ⅼ': 'l', 'ⅿ': 'm'
    }

    def __init__(self):
        self.ip_pattern = re.compile(
            r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        )
        # Pre-compile regex patterns for performance
        self.hex_pattern = re.compile(r'%[0-9a-fA-F]{2}')
        self.punycode_pattern = re.compile(r'xn--[a-z0-9]+')
        self.base64_pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')

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

                # NEW: Typosquatting detection
                'typosquatting_target': self._detect_typosquatting(domain),
                'typosquatting_score': self._get_typosquatting_score(domain),
                'is_typosquatting': self._get_typosquatting_score(domain) > 0.7,

                # NEW: Homograph attack detection
                'has_homograph': self._detect_homograph(decoded_url),
                'homograph_chars': self._find_homograph_chars(decoded_url),

                # NEW: URL obfuscation detection
                'has_encoded_chars': bool(self.hex_pattern.search(decoded_url)),
                'encoded_char_count': len(self.hex_pattern.findall(url)),
                'has_punycode': bool(self.punycode_pattern.search(domain or '')),
                'has_data_uri': decoded_url.lower().startswith('data:'),
                'has_javascript_uri': 'javascript:' in decoded_url.lower(),
                'has_base64': bool(self.base64_pattern.search(decoded_url)),

                # NEW: Suspicious URL patterns
                'has_redirect_param': any(p in decoded_url.lower() for p in ['redirect=', 'url=', 'next=', 'goto=', 'return=']),
                'has_login_form_pattern': any(p in decoded_url.lower() for p in ['/login', '/signin', '/auth', '/verify', '/secure']),
                'has_fake_extension': self._has_fake_extension(parsed.path),
                'consecutive_digits': self._max_consecutive_digits(decoded_url),
                'random_looking': self._is_random_looking(domain),

                # NEW: Domain analysis
                'domain_has_brand': self._domain_contains_brand(domain),
                'suspicious_subdomain': self._is_suspicious_subdomain(subdomain),
                'tld_in_subdomain': self._has_tld_in_subdomain(subdomain),

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
        subdomain_lower = subdomain.lower()
        return any(brand in subdomain_lower for brand in self.TARGET_BRANDS)

    def _levenshtein_distance(self, s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between two strings."""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]

    def _detect_typosquatting(self, domain: str) -> Optional[str]:
        """Detect if domain is typosquatting a known brand."""
        if not domain:
            return None

        # Extract just the main domain name (without TLD)
        domain_parts = domain.lower().split('.')
        if len(domain_parts) < 2:
            return None
        main_domain = domain_parts[0]

        # Check each brand for similarity
        for brand in self.TARGET_BRANDS:
            # Skip if exact match (legitimate)
            if main_domain == brand:
                continue

            # Check Levenshtein distance
            distance = self._levenshtein_distance(main_domain, brand)
            max_len = max(len(main_domain), len(brand))

            # If very similar (1-2 char difference), likely typosquatting
            if distance <= 2 and max_len >= 4:
                return brand

            # Check for common typosquatting patterns
            # Character substitution (0 for o, 1 for l, etc.)
            normalized = main_domain.replace('0', 'o').replace('1', 'l').replace('1', 'i')
            if normalized == brand or self._levenshtein_distance(normalized, brand) <= 1:
                return brand

            # Check for extra/missing characters
            if brand in main_domain and len(main_domain) <= len(brand) + 3:
                return brand

            # Check for character swaps
            if len(main_domain) == len(brand):
                diff_count = sum(1 for a, b in zip(main_domain, brand) if a != b)
                if diff_count <= 2:
                    return brand

        return None

    def _get_typosquatting_score(self, domain: str) -> float:
        """Get a score indicating likelihood of typosquatting (0-1)."""
        if not domain:
            return 0.0

        domain_parts = domain.lower().split('.')
        if len(domain_parts) < 2:
            return 0.0
        main_domain = domain_parts[0]

        best_score = 0.0
        for brand in self.TARGET_BRANDS:
            if main_domain == brand:
                continue  # Exact match is not typosquatting

            distance = self._levenshtein_distance(main_domain, brand)
            max_len = max(len(main_domain), len(brand))

            if max_len == 0:
                continue

            # Calculate similarity score
            similarity = 1 - (distance / max_len)

            # Higher score for closer matches
            if similarity > 0.7:  # At least 70% similar
                score = similarity
                # Bonus for same length
                if len(main_domain) == len(brand):
                    score = min(score + 0.1, 1.0)
                best_score = max(best_score, score)

        return round(best_score, 4)

    def _detect_homograph(self, url: str) -> bool:
        """Detect if URL contains homograph characters."""
        for char in url:
            if char in self.HOMOGRAPH_MAP:
                return True
        return False

    def _find_homograph_chars(self, url: str) -> List[str]:
        """Find all homograph characters in URL."""
        found = []
        for char in url:
            if char in self.HOMOGRAPH_MAP:
                found.append(f"{char}→{self.HOMOGRAPH_MAP[char]}")
        return found

    def _has_fake_extension(self, path: str) -> bool:
        """Check for fake file extensions used in phishing."""
        fake_extensions = ['.php', '.asp', '.aspx', '.jsp', '.cgi', '.pl']
        safe_extensions = ['.html', '.htm', '.pdf', '.jpg', '.png', '.gif', '.css', '.js']

        path_lower = path.lower()
        # Check if path ends with executable extension followed by params
        for ext in fake_extensions:
            if ext in path_lower:
                return True
        # Check for double extensions
        if path_lower.count('.') >= 2:
            parts = path_lower.split('.')
            if len(parts) >= 3 and parts[-2] in ['exe', 'zip', 'pdf', 'doc']:
                return True
        return False

    def _max_consecutive_digits(self, text: str) -> int:
        """Find maximum consecutive digits in text."""
        max_count = 0
        current_count = 0
        for char in text:
            if char.isdigit():
                current_count += 1
                max_count = max(max_count, current_count)
            else:
                current_count = 0
        return max_count

    def _is_random_looking(self, domain: str) -> bool:
        """Check if domain looks randomly generated."""
        if not domain:
            return False

        main_domain = domain.split('.')[0] if domain else ''
        if len(main_domain) < 8:
            return False

        # Check consonant/vowel ratio
        vowels = set('aeiou')
        consonants = set('bcdfghjklmnpqrstvwxyz')

        v_count = sum(1 for c in main_domain.lower() if c in vowels)
        c_count = sum(1 for c in main_domain.lower() if c in consonants)

        if c_count > 0:
            ratio = v_count / c_count
            # Normal English words have ratio around 0.4-0.6
            if ratio < 0.15 or ratio > 1.5:
                return True

        # Check for repeating patterns
        if len(set(main_domain)) < len(main_domain) / 3:
            return True

        return False

    def _domain_contains_brand(self, domain: str) -> Optional[str]:
        """Check if domain contains a brand name (but isn't the actual brand)."""
        if not domain:
            return None

        domain_lower = domain.lower()
        for brand in self.TARGET_BRANDS:
            # Check if brand is in domain but domain isn't the actual brand site
            if brand in domain_lower:
                # Extract the main domain without TLD
                parts = domain_lower.split('.')
                main_domain = parts[0] if parts else ''
                # If main domain contains brand but isn't exactly the brand
                if brand in main_domain and main_domain != brand:
                    return brand
        return None

    def _is_suspicious_subdomain(self, subdomain: str) -> bool:
        """Check if subdomain is suspicious."""
        if not subdomain:
            return False

        subdomain_lower = subdomain.lower()
        suspicious_patterns = [
            'secure', 'login', 'signin', 'verify', 'account', 'update',
            'confirm', 'banking', 'support', 'help', 'service', 'client',
            'user', 'member', 'portal', 'auth', 'sso', 'id', 'identity'
        ]

        for pattern in suspicious_patterns:
            if pattern in subdomain_lower:
                return True

        # Check for brand + suspicious word combo
        for brand in self.TARGET_BRANDS:
            if brand in subdomain_lower:
                return True

        return False

    def _has_tld_in_subdomain(self, subdomain: str) -> bool:
        """Check if subdomain contains a TLD (e.g., paypal.com.evil.com)."""
        if not subdomain:
            return False

        common_tlds = ['com', 'org', 'net', 'co', 'io', 'me', 'us', 'uk', 'edu', 'gov']
        subdomain_lower = subdomain.lower()

        for tld in common_tlds:
            if f'.{tld}.' in f'.{subdomain_lower}.' or subdomain_lower.endswith(f'.{tld}'):
                return True
        return False

    def get_feature_vector(self, url: str) -> Tuple[List[float], Dict[str, Any]]:
        """Get numerical feature vector for ML model."""
        features = self.extract_features(url)

        # Create numerical feature vector with all features
        vector = [
            # Original features (keep for model compatibility)
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

    def get_enhanced_feature_vector(self, url: str) -> Tuple[List[float], Dict[str, Any]]:
        """Get enhanced numerical feature vector with all new features."""
        features = self.extract_features(url)

        # Extended feature vector including all new features
        vector = [
            # Basic length features
            features.get('url_length', 0),
            features.get('domain_length', 0),
            features.get('subdomain_length', 0),
            features.get('path_length', 0),
            features.get('query_length', 0),

            # Character count features
            features.get('num_dots', 0),
            features.get('num_hyphens', 0),
            features.get('num_underscores', 0),
            features.get('num_slashes', 0),
            features.get('num_at_symbols', 0),
            features.get('num_digits', 0),
            features.get('num_special_chars', 0),
            features.get('num_ampersands', 0),
            features.get('num_equals', 0),

            # Boolean flags
            1 if features.get('has_ip', False) else 0,
            1 if features.get('has_https', False) else 0,
            1 if features.get('has_port', False) else 0,
            1 if features.get('has_at_symbol', False) else 0,
            1 if features.get('has_double_slash_redirect', False) else 0,

            # Calculated features
            features.get('entropy', 0),
            features.get('digit_ratio', 0),
            features.get('letter_ratio', 0),

            # Suspicious patterns
            1 if features.get('suspicious_tld', False) else 0,
            features.get('subdomain_count', 0),
            features.get('num_suspicious_keywords', 0),
            1 if features.get('is_shortened', False) else 0,
            1 if features.get('has_brand_in_subdomain', False) else 0,
            1 if features.get('excessive_subdomains', False) else 0,
            1 if features.get('long_domain', False) else 0,

            # NEW: Typosquatting features
            features.get('typosquatting_score', 0),
            1 if features.get('is_typosquatting', False) else 0,

            # NEW: Homograph features
            1 if features.get('has_homograph', False) else 0,
            len(features.get('homograph_chars', [])),

            # NEW: Obfuscation features
            1 if features.get('has_encoded_chars', False) else 0,
            features.get('encoded_char_count', 0),
            1 if features.get('has_punycode', False) else 0,
            1 if features.get('has_data_uri', False) else 0,
            1 if features.get('has_javascript_uri', False) else 0,
            1 if features.get('has_base64', False) else 0,

            # NEW: Suspicious URL patterns
            1 if features.get('has_redirect_param', False) else 0,
            1 if features.get('has_login_form_pattern', False) else 0,
            1 if features.get('has_fake_extension', False) else 0,
            features.get('consecutive_digits', 0),
            1 if features.get('random_looking', False) else 0,

            # NEW: Domain analysis
            1 if features.get('domain_has_brand') else 0,
            1 if features.get('suspicious_subdomain', False) else 0,
            1 if features.get('tld_in_subdomain', False) else 0,
        ]

        return vector, features


# Singleton instance
url_analyzer = URLAnalyzer()
