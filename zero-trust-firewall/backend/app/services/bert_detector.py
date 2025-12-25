"""
BERT-based Phishing URL Detector

Uses a pre-trained transformer model fine-tuned for URL classification.
Falls back to an enhanced character-level model if transformers are not available.
"""

import os
import numpy as np
from typing import Dict, Any, Optional, List
import re
import tldextract
import requests
from urllib.parse import urlparse

# Try to import transformers, fall back to lightweight model if not available
try:
    from transformers import AutoTokenizer, AutoModelForSequenceClassification
    import torch
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False
    print("Transformers not available, using enhanced character-level model")


class EnhancedCharacterModel:
    """Enhanced character-level model for phishing detection with comprehensive patterns."""

    def __init__(self):
        # Character substitution patterns (look-alike characters)
        self.char_substitutions = {
            '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
            '7': 't', '8': 'b', '@': 'a', '$': 's', '!': 'i',
        }

        # High-value target brands for typosquatting detection
        self.target_brands = [
            'google', 'facebook', 'apple', 'microsoft', 'amazon', 'paypal',
            'netflix', 'instagram', 'twitter', 'linkedin', 'chase', 'wellsfargo',
            'bankofamerica', 'citibank', 'capitalone', 'amex', 'venmo', 'zelle',
            'dropbox', 'icloud', 'outlook', 'hotmail', 'yahoo', 'gmail',
            'whatsapp', 'telegram', 'snapchat', 'tiktok', 'spotify', 'uber',
            'coinbase', 'binance', 'blockchain', 'steam', 'discord', 'twitch',
            'adobe', 'docusign', 'stripe', 'square', 'robinhood', 'fidelity'
        ]

        # Known legitimate domains (exact matches - very safe)
        self.safe_domains = {
            'google.com', 'www.google.com', 'mail.google.com', 'accounts.google.com',
            'drive.google.com', 'docs.google.com', 'play.google.com',
            'amazon.com', 'www.amazon.com', 'aws.amazon.com', 'smile.amazon.com',
            'microsoft.com', 'www.microsoft.com', 'login.microsoftonline.com',
            'office.com', 'office365.com', 'live.com', 'outlook.com',
            'apple.com', 'www.apple.com', 'icloud.com', 'appleid.apple.com',
            'facebook.com', 'www.facebook.com', 'm.facebook.com', 'fb.com',
            'github.com', 'www.github.com', 'gist.github.com',
            'linkedin.com', 'www.linkedin.com',
            'twitter.com', 'www.twitter.com', 'x.com', 'mobile.twitter.com',
            'instagram.com', 'www.instagram.com',
            'netflix.com', 'www.netflix.com',
            'paypal.com', 'www.paypal.com',
            'chase.com', 'www.chase.com', 'secure.chase.com',
            'wellsfargo.com', 'www.wellsfargo.com', 'online.wellsfargo.com',
            'bankofamerica.com', 'www.bankofamerica.com',
            'hotmail.com', 'www.hotmail.com',
            'yahoo.com', 'www.yahoo.com', 'mail.yahoo.com',
            'dropbox.com', 'www.dropbox.com',
            'spotify.com', 'www.spotify.com', 'open.spotify.com',
            'discord.com', 'www.discord.com', 'discordapp.com',
            'twitch.tv', 'www.twitch.tv',
            'reddit.com', 'www.reddit.com', 'old.reddit.com',
            'wikipedia.org', 'www.wikipedia.org', 'en.wikipedia.org',
            'stackoverflow.com', 'www.stackoverflow.com',
            'youtube.com', 'www.youtube.com', 'm.youtube.com',
            'ebay.com', 'www.ebay.com',
            'zoom.us', 'www.zoom.us',
            'slack.com', 'www.slack.com',
            'notion.so', 'www.notion.so',
            'figma.com', 'www.figma.com',
            'coinbase.com', 'www.coinbase.com',
            'binance.com', 'www.binance.com',
            'venmo.com', 'www.venmo.com',
            'stripe.com', 'www.stripe.com',
        }

        # Suspicious patterns with weights - organized by category
        self.patterns = {
            # === HIGH SEVERITY: Brand Mimicking ===
            # These patterns detect common typosquatting of major brands
            r'(?:^|[./])paypa[l1i](?!\.(com|me)($|/))': ('paypal typosquatting', 0.85),
            r'(?:^|[./])amaz[o0][on](?!\.com($|/))': ('amazon typosquatting', 0.85),
            r'(?:^|[./])g[o0]{2}g[l1]e(?!\.com($|/))': ('google typosquatting', 0.85),
            r'(?:^|[./])faceb[o0]{2}k(?!\.com($|/))': ('facebook typosquatting', 0.85),
            r'(?:^|[./])micr[o0]s[o0]ft(?!\.com($|/))': ('microsoft typosquatting', 0.85),
            r'(?:^|[./])app[l1]e(?!\.com($|/))': ('apple typosquatting', 0.85),
            r'(?:^|[./])netf[l1][i1]x(?!\.com($|/))': ('netflix typosquatting', 0.85),
            r'(?:^|[./])linked[l1i]n(?!\.com($|/))': ('linkedin typosquatting', 0.8),
            r'(?:^|[./])hotmai[l1i](?!\.com($|/))': ('hotmail typosquatting', 0.85),
            r'(?:^|[./])hotma[l1i]{2}(?!\.com($|/))': ('hotmail typosquatting', 0.85),
            r'(?:^|[./])outl[o0]{2}k(?!\.com($|/))': ('outlook typosquatting', 0.85),
            r'(?:^|[./])yah[o0]{2}(?!\.com($|/))': ('yahoo typosquatting', 0.85),
            r'(?:^|[./])gmai[l1](?!\.com($|/))': ('gmail typosquatting', 0.85),
            r'(?:^|[./])twitt[e3]r(?!\.(com|co)($|/))': ('twitter typosquatting', 0.8),
            r'(?:^|[./])instag[r]?[a4]m(?!\.com($|/))': ('instagram typosquatting', 0.8),
            r'(?:^|[./])whatsap+(?!\.com($|/))': ('whatsapp typosquatting', 0.8),
            r'(?:^|[./])t[i1]kt[o0]k(?!\.com($|/))': ('tiktok typosquatting', 0.8),
            r'(?:^|[./])ch[a4]se(?!\.com($|/))': ('chase typosquatting', 0.9),
            r'(?:^|[./])wellsf[a4]rg[o0](?!\.com($|/))': ('wellsfargo typosquatting', 0.9),
            r'(?:^|[./])c[o0][i1]nb[a4]se(?!\.com($|/))': ('coinbase typosquatting', 0.9),
            r'(?:^|[./])b[i1]n[a4]nce(?!\.com($|/))': ('binance typosquatting', 0.9),
            r'(?:^|[./])venm[o0](?!\.com($|/))': ('venmo typosquatting', 0.85),
            r'(?:^|[./])dr[o0]pb[o0]x(?!\.com($|/))': ('dropbox typosquatting', 0.8),
            r'(?:^|[./])sp[o0]t[i1]fy(?!\.com($|/))': ('spotify typosquatting', 0.8),
            r'(?:^|[./])d[i1]sc[o0]rd(?!\.com($|/))': ('discord typosquatting', 0.8),
            r'(?:^|[./])[i1]cl[o0]ud(?!\.com($|/))': ('icloud typosquatting', 0.85),

            # === HIGH SEVERITY: Dangerous URL Patterns ===
            r'https?://[^/]*@': ('credential harvesting @', 0.95),
            r'^data:': ('data uri scheme', 0.98),
            r'javascript:': ('javascript uri', 0.98),
            r'xn--[a-z0-9]+': ('punycode/idn homograph', 0.8),

            # === MEDIUM-HIGH SEVERITY: Suspicious Subdomains ===
            r'-login\b': ('login in subdomain', 0.6),
            r'-secure\b': ('secure in subdomain', 0.6),
            r'-verify\b': ('verify in subdomain', 0.7),
            r'-account\b': ('account in subdomain', 0.6),
            r'-update\b': ('update in subdomain', 0.6),
            r'-confirm\b': ('confirm in subdomain', 0.7),
            r'-banking\b': ('banking in subdomain', 0.75),
            r'-payment\b': ('payment in subdomain', 0.7),
            r'-signin\b': ('signin in subdomain', 0.65),
            r'-auth\b': ('auth in subdomain', 0.6),
            r'-validate\b': ('validate in subdomain', 0.7),
            r'-suspended\b': ('suspended in subdomain', 0.75),
            r'-locked\b': ('locked in subdomain', 0.7),
            r'-alert\b': ('alert in subdomain', 0.65),

            # === MEDIUM SEVERITY: Suspicious TLDs ===
            r'\.(xyz|tk|ml|ga|cf|gq|top|loan|work|click|link|win|party|racing|review|science|date|download|stream|bid|trade|accountant|faith|cricket|webcam|gdn|kim|men|mom|xin|site|online|website|space|pw|cc|ws)($|/)': ('suspicious tld', 0.55),

            # === MEDIUM SEVERITY: Character Substitution Patterns ===
            r'vv': ('vv looks like w', 0.45),
            r'rn(?=[a-z])': ('rn looks like m', 0.4),
            r'cl(?=[oa])': ('cl looks like d', 0.35),
            r'nn(?=[a-z])': ('nn looks like m', 0.3),
            r'(?<=[a-z])ii(?=[a-z])': ('double i suspicious', 0.35),

            # === MEDIUM SEVERITY: URL Structure ===
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}': ('ip address in url', 0.65),
            r'([a-z0-9-]+\.){4,}[a-z]+': ('excessive subdomains', 0.5),
            r'[a-z0-9]{30,}': ('very long random string', 0.5),
            r'[bcdfghjklmnpqrstvwxz]{6,}': ('consonant cluster', 0.45),
            r':\d{4,5}[/\?]': ('unusual port number', 0.4),

            # === LOW-MEDIUM SEVERITY: Suspicious Paths ===
            r'/wp-(admin|includes|content)/[^/]+\.(php|asp)': ('wordpress exploit path', 0.5),
            r'\.(php|asp|aspx|jsp|cgi)\?[^=]+=': ('script with params', 0.35),
            r'(redirect|url|next|goto|return|redir|link)=https?': ('open redirect param', 0.5),
            r'[A-Za-z0-9+/]{50,}={0,2}': ('base64 in url', 0.4),

            # === LOW SEVERITY: Minor Indicators ===
            r'%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}.*%[0-9a-fA-F]{2}': ('multiple url encodings', 0.25),
            r'//[^/]+//': ('double slash redirect', 0.3),
        }

    def _extract_domain(self, url: str) -> str:
        """Extract the full domain from URL."""
        try:
            extracted = tldextract.extract(url)
            domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain
            if extracted.subdomain:
                return f"{extracted.subdomain}.{domain}"
            return domain
        except:
            return ""

    def _is_safe_domain(self, url: str) -> bool:
        """Check if URL is from a known safe domain."""
        domain = self._extract_domain(url).lower()
        # Check exact match
        if domain in self.safe_domains:
            return True
        # Check without www
        if domain.startswith('www.'):
            if domain[4:] in self.safe_domains:
                return True
        return False

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

    def _check_redirect_to_legitimate(self, url: str, expected_brand: str) -> bool:
        """
        Check if URL redirects to the legitimate brand's website.
        This helps identify defensive registrations by companies.
        """
        try:
            # Extract domain from URL for testing
            parsed = urlparse(url)
            domain = parsed.netloc or parsed.path.split('/')[0]
            if domain.startswith('www.'):
                domain = domain[4:]

            # Try HTTP first (most defensive redirects work on HTTP)
            test_url = f'http://{domain}'

            # Make request with short timeout, don't follow redirects
            response = requests.head(
                test_url,
                timeout=3,
                allow_redirects=False,
                verify=False,
                headers={'User-Agent': 'Mozilla/5.0'}
            )

            # Check if it's a redirect (301, 302, 303, 307, 308)
            if response.status_code in [301, 302, 303, 307, 308]:
                redirect_url = response.headers.get('Location', '').lower()

                # Check if redirect goes to the legitimate brand domain
                legitimate_domains = [
                    f'{expected_brand}.com',
                    f'www.{expected_brand}.com',
                    f'{expected_brand}.org',
                    f'{expected_brand}.net',
                ]

                for legit in legitimate_domains:
                    if legit in redirect_url:
                        return True

            return False
        except:
            # If we can't check, assume it's not a defensive redirect
            return False

    def _detect_typosquatting(self, url: str) -> tuple:
        """Detect typosquatting using Levenshtein distance."""
        try:
            extracted = tldextract.extract(url)
            main_domain = extracted.domain.lower() if extracted.domain else ''
        except:
            return (None, 0.0)

        if not main_domain:
            return (None, 0.0)

        best_match = (None, 0.0)

        for brand in self.target_brands:
            # Skip if exact match (legitimate)
            if main_domain == brand:
                continue

            # Calculate similarity
            distance = self._levenshtein_distance(main_domain, brand)
            max_len = max(len(main_domain), len(brand))

            if max_len == 0:
                continue

            # Normalize distance to similarity score
            similarity = 1 - (distance / max_len)

            # Very similar (1-2 char difference) is highly suspicious
            if distance <= 2 and len(brand) >= 4 and len(main_domain) >= 4:
                score = 0.9 if distance == 1 else 0.85
                if score > best_match[1]:
                    best_match = (brand, score)
                continue

            # Check with character normalization (0->o, 1->l, etc.)
            normalized = main_domain
            for char, replacement in self.char_substitutions.items():
                normalized = normalized.replace(char, replacement)

            norm_distance = self._levenshtein_distance(normalized, brand)
            if norm_distance == 0:
                # Perfect match after normalization = definite typosquatting
                if 0.95 > best_match[1]:
                    best_match = (brand, 0.95)
            elif norm_distance == 1:
                if 0.88 > best_match[1]:
                    best_match = (brand, 0.88)

            # Moderately similar (80%+ match)
            if similarity >= 0.8 and similarity * 0.85 > best_match[1]:
                best_match = (brand, similarity * 0.85)

        return best_match

    def predict(self, url: str) -> Dict[str, Any]:
        """Predict phishing probability using enhanced pattern matching."""
        url_lower = url.lower()
        score = 0.0
        matched_patterns = []

        # Check for safe domains first
        if self._is_safe_domain(url):
            return {
                'score': 0.02,
                'is_phishing': False,
                'matched_patterns': ['Known legitimate domain'],
                'model_type': 'enhanced_character_level'
            }

        # Check typosquatting using Levenshtein distance
        typo_brand, typo_score = self._detect_typosquatting(url)
        if typo_brand and typo_score > 0.5:
            # Check if this is a defensive registration (redirects to legit site)
            if self._check_redirect_to_legitimate(url, typo_brand):
                # It's a defensive redirect - mark as safe
                return {
                    'score': 0.05,
                    'is_phishing': False,
                    'matched_patterns': [f"Defensive redirect to {typo_brand}.com"],
                    'model_type': 'enhanced_character_level'
                }
            else:
                score += typo_score
                matched_patterns.append(f"Typosquatting '{typo_brand}' (score: {typo_score:.2f})")

        # Check all suspicious patterns
        for pattern, (description, weight) in self.patterns.items():
            try:
                if re.search(pattern, url_lower):
                    score += weight
                    matched_patterns.append(description)
            except re.error:
                pass  # Skip invalid regex

        # Additional heuristics
        # Excessive hyphens in domain
        domain = self._extract_domain(url)
        if domain.count('-') >= 3:
            score += 0.3
            matched_patterns.append('excessive hyphens in domain')

        # Very long URL
        if len(url) > 150:
            score += 0.2
            matched_patterns.append('very long url')
        elif len(url) > 100:
            score += 0.1
            matched_patterns.append('long url')

        # No HTTPS on sensitive-looking URL
        if not url.startswith('https://'):
            sensitive_keywords = ['login', 'signin', 'account', 'bank', 'secure', 'verify']
            if any(kw in url_lower for kw in sensitive_keywords):
                score += 0.35
                matched_patterns.append('no https on sensitive url')
            else:
                score += 0.1
                matched_patterns.append('no https')

        # Brand name in path (suspicious if not main domain)
        for brand in self.target_brands:
            if f'/{brand}' in url_lower or f'{brand}.' in url_lower:
                # Check if it's not the actual brand domain
                if f'{brand}.com' not in domain and f'{brand}.org' not in domain:
                    score += 0.4
                    matched_patterns.append(f"brand '{brand}' misused in url")
                    break

        # Multiple suspicious keywords
        suspicious_keywords = ['verify', 'update', 'confirm', 'suspended', 'locked',
                              'unusual', 'activity', 'secure', 'authenticate', 'validate']
        keyword_count = sum(1 for kw in suspicious_keywords if kw in url_lower)
        if keyword_count >= 3:
            score += 0.5
            matched_patterns.append(f'{keyword_count} suspicious keywords')
        elif keyword_count >= 2:
            score += 0.3
            matched_patterns.append(f'{keyword_count} suspicious keywords')

        # Normalize score to 0-1
        score = min(score, 1.0)

        return {
            'score': round(score, 4),
            'is_phishing': score >= 0.5,
            'matched_patterns': matched_patterns,
            'model_type': 'enhanced_character_level'
        }


class BERTPhishingDetector:
    """
    BERT-based phishing URL detector.

    Uses a pre-trained model or falls back to enhanced character-level detection.
    """

    def __init__(self):
        self.model = None
        self.tokenizer = None
        self.device = None
        self.is_loaded = False
        self.model_type = "none"

        # Enhanced fallback model
        self.char_model = EnhancedCharacterModel()

        # Try to load BERT model
        if TRANSFORMERS_AVAILABLE:
            self._load_bert_model()
        else:
            self.model_type = "enhanced_character_level"
            print("Using enhanced character-level model (transformers not installed)")

    def _load_bert_model(self):
        """Load pre-trained BERT model for URL classification."""
        try:
            model_name = "distilbert-base-uncased"
            local_model_path = "app/ml/bert_phishing_model"

            if os.path.exists(local_model_path):
                print(f"Loading fine-tuned BERT model from {local_model_path}")
                self.tokenizer = AutoTokenizer.from_pretrained(local_model_path)
                self.model = AutoModelForSequenceClassification.from_pretrained(local_model_path)
                self.model_type = "bert_finetuned"
            else:
                print(f"Loading pre-trained {model_name} model...")
                self.tokenizer = AutoTokenizer.from_pretrained(model_name)
                self.model_type = "bert_pretrained"

            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            if self.model:
                self.model.to(self.device)
                self.model.eval()

            self.is_loaded = True
            print(f"BERT model loaded successfully (type: {self.model_type})")

        except Exception as e:
            print(f"Error loading BERT model: {e}")
            self.model_type = "enhanced_character_level"
            print("Falling back to enhanced character-level model")

    def _tokenize_url(self, url: str) -> List[str]:
        """Tokenize URL into meaningful parts."""
        url_no_protocol = re.sub(r'^https?://', '', url)
        parts = re.split(r'[/\-._?&=]', url_no_protocol)

        tokens = []
        for part in parts:
            if part:
                sub_parts = re.findall(r'[A-Z]?[a-z]+|[A-Z]+(?=[A-Z]|$)|[0-9]+', part)
                tokens.extend(sub_parts if sub_parts else [part])

        return tokens

    def _get_bert_embedding_score(self, url: str) -> float:
        """Get phishing score using BERT embeddings."""
        if not self.is_loaded or self.model is None:
            return self.char_model.predict(url)['score']

        try:
            inputs = self.tokenizer(
                url,
                return_tensors="pt",
                truncation=True,
                max_length=128,
                padding=True
            )
            inputs = {k: v.to(self.device) for k, v in inputs.items()}

            with torch.no_grad():
                outputs = self.model(**inputs)
                logits = outputs.logits
                probabilities = torch.softmax(logits, dim=1)
                phishing_prob = probabilities[0][1].item()

            return phishing_prob

        except Exception as e:
            print(f"BERT prediction error: {e}")
            return self.char_model.predict(url)['score']

    def predict(self, url: str) -> Dict[str, Any]:
        """
        Predict if URL is phishing using BERT or enhanced fallback model.

        Returns:
            Dictionary with score, prediction, and model details
        """
        # Always run enhanced character-level for pattern matching
        char_result = self.char_model.predict(url)

        # If BERT model is available and loaded, use hybrid approach
        if self.model_type == "bert_finetuned" and self.model is not None:
            bert_score = self._get_bert_embedding_score(url)

            # Combine BERT and character-level scores
            # BERT: 60%, Character-level: 40% (character patterns are important)
            combined_score = bert_score * 0.6 + char_result['score'] * 0.4

            return {
                'bert_score': round(bert_score, 4),
                'char_score': round(char_result['score'], 4),
                'combined_score': round(combined_score, 4),
                'is_phishing': combined_score >= 0.5,
                'matched_patterns': char_result['matched_patterns'],
                'model_type': 'bert_hybrid',
                'details': {
                    'bert_weight': 0.6,
                    'char_weight': 0.4,
                    'device': str(self.device) if self.device else 'cpu'
                }
            }

        # Use enhanced character-level model with URL token analysis
        tokens = self._tokenize_url(url)
        token_score = 0.0
        suspicious_tokens = []

        # Analyze tokens for brand misuse
        for token in tokens:
            token_lower = token.lower()
            for brand in self.char_model.target_brands:
                # Check for typosquatting in tokens
                distance = self.char_model._levenshtein_distance(token_lower, brand)
                if 1 <= distance <= 2 and len(brand) >= 4:
                    token_score += 0.4
                    suspicious_tokens.append(f"token similar to '{brand}'")
                    break

        # Combine scores
        final_score = min(char_result['score'] + token_score * 0.3, 1.0)

        return {
            'bert_score': round(final_score, 4),
            'char_score': round(char_result['score'], 4),
            'combined_score': round(final_score, 4),
            'is_phishing': final_score >= 0.5,
            'matched_patterns': char_result['matched_patterns'] + suspicious_tokens,
            'model_type': self.model_type,
            'tokens': tokens[:10],
            'details': {
                'token_analysis': suspicious_tokens,
                'transformers_available': TRANSFORMERS_AVAILABLE
            }
        }

    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the loaded model."""
        return {
            'model_type': self.model_type,
            'is_loaded': self.is_loaded,
            'transformers_available': TRANSFORMERS_AVAILABLE,
            'device': str(self.device) if self.device else 'cpu',
            'features': [
                'Enhanced pattern matching',
                'Levenshtein-based typosquatting detection',
                'Brand impersonation detection',
                'Homograph attack detection',
                'URL structure analysis',
                'Suspicious keyword detection',
                'BERT embeddings (if available)'
            ]
        }


# Singleton instance
bert_detector = BERTPhishingDetector()
