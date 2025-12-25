import os
import pickle
import numpy as np
import tldextract
from typing import Dict, Any, Tuple, Optional
import joblib
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from app.core.config import settings
from .url_analyzer import url_analyzer


class PhishingMLDetector:
    """Machine Learning based phishing URL detector."""

    # Known legitimate domains - these should get very low ML scores
    KNOWN_LEGITIMATE_DOMAINS = {
        'google.com', 'www.google.com', 'mail.google.com', 'drive.google.com',
        'amazon.com', 'www.amazon.com',
        'microsoft.com', 'www.microsoft.com', 'login.microsoftonline.com',
        'apple.com', 'www.apple.com', 'icloud.com',
        'facebook.com', 'www.facebook.com',
        'twitter.com', 'www.twitter.com', 'x.com',
        'linkedin.com', 'www.linkedin.com',
        'github.com', 'www.github.com',
        'netflix.com', 'www.netflix.com',
        'youtube.com', 'www.youtube.com',
        'instagram.com', 'www.instagram.com',
        'paypal.com', 'www.paypal.com',
        'ebay.com', 'www.ebay.com',
        'chase.com', 'www.chase.com',
        'bankofamerica.com', 'www.bankofamerica.com',
        'wellsfargo.com', 'www.wellsfargo.com',
        'reddit.com', 'www.reddit.com',
        'wikipedia.org', 'www.wikipedia.org',
        'stackoverflow.com', 'www.stackoverflow.com',
        'dropbox.com', 'www.dropbox.com',
        'spotify.com', 'www.spotify.com',
        'zoom.us', 'www.zoom.us',
        'slack.com', 'www.slack.com',
        'notion.so', 'www.notion.so',
        'figma.com', 'www.figma.com',
        'aws.amazon.com', 'console.aws.amazon.com',
        'portal.azure.com', 'cloud.google.com',
        'outlook.live.com', 'outlook.com',
        'yahoo.com', 'mail.yahoo.com',
        'cnn.com', 'www.cnn.com',
        'bbc.com', 'www.bbc.com',
        'nytimes.com', 'www.nytimes.com',
        'walmart.com', 'www.walmart.com',
        'target.com', 'www.target.com',
        'bestbuy.com', 'www.bestbuy.com',
        'etsy.com', 'www.etsy.com',
        'venmo.com', 'www.venmo.com',
    }

    def __init__(self):
        self.model: Optional[RandomForestClassifier] = None
        self.scaler: Optional[StandardScaler] = None
        self.model_path = settings.ML_MODEL_PATH
        self.threshold = settings.ML_THRESHOLD
        self.is_loaded = False

        # Feature names for reference
        self.feature_names = [
            'url_length', 'domain_length', 'subdomain_length', 'path_length',
            'query_length', 'num_dots', 'num_hyphens', 'num_underscores',
            'num_slashes', 'num_at_symbols', 'num_digits', 'num_special_chars',
            'has_ip', 'has_https', 'has_port', 'has_at_symbol', 'entropy',
            'digit_ratio', 'letter_ratio', 'suspicious_tld', 'subdomain_count',
            'num_suspicious_keywords', 'is_shortened', 'has_brand_in_subdomain',
            'excessive_subdomains', 'long_domain'
        ]

        # Try to load existing model
        self._load_model()

    def _load_model(self) -> bool:
        """Load trained model from disk."""
        try:
            if os.path.exists(self.model_path):
                # Try joblib first (legacy format)
                try:
                    data = joblib.load(self.model_path)
                except Exception:
                    # Fall back to pickle (new training script format)
                    with open(self.model_path, 'rb') as f:
                        data = pickle.load(f)

                self.model = data['model']
                self.scaler = data['scaler']
                self.is_loaded = True
                print(f"ML model loaded successfully from {self.model_path}")
                return True
        except Exception as e:
            print(f"Error loading model: {e}")

        # Initialize with default model if not found
        self._initialize_default_model()
        return False

    def _initialize_default_model(self):
        """Initialize a default model with realistic phishing URL training data."""
        # Use actual URL patterns for training instead of random synthetic data
        # This provides much better detection accuracy

        # Realistic legitimate URLs
        legitimate_urls = [
            # Major tech companies
            "https://www.google.com/search?q=weather",
            "https://www.amazon.com/dp/B08N5WRWNW",
            "https://www.microsoft.com/en-us/windows",
            "https://www.apple.com/iphone",
            "https://www.facebook.com/",
            "https://www.twitter.com/home",
            "https://www.linkedin.com/feed/",
            "https://www.github.com/explore",
            "https://www.netflix.com/browse",
            "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
            # Banks and financial
            "https://www.chase.com/personal/checking",
            "https://www.bankofamerica.com/",
            "https://www.wellsfargo.com/",
            "https://www.paypal.com/myaccount/home",
            "https://www.venmo.com/",
            # E-commerce
            "https://www.ebay.com/",
            "https://www.walmart.com/",
            "https://www.target.com/",
            "https://www.bestbuy.com/",
            "https://www.etsy.com/",
            # News and media
            "https://www.cnn.com/",
            "https://www.bbc.com/news",
            "https://www.nytimes.com/",
            "https://www.reddit.com/r/all",
            "https://www.medium.com/",
            # Cloud services
            "https://console.aws.amazon.com/",
            "https://portal.azure.com/",
            "https://cloud.google.com/",
            "https://www.dropbox.com/home",
            "https://drive.google.com/drive/my-drive",
            # Email
            "https://mail.google.com/mail/u/0/",
            "https://outlook.live.com/mail/",
            "https://mail.yahoo.com/",
            # Misc legitimate
            "https://www.wikipedia.org/",
            "https://stackoverflow.com/questions",
            "https://www.spotify.com/",
            "https://www.zoom.us/",
            "https://www.slack.com/",
            "https://www.notion.so/",
            "https://www.figma.com/",
            # Short legitimate URLs
            "https://google.com",
            "https://amazon.com",
            "https://apple.com",
            "https://microsoft.com",
            "https://github.com",
        ]

        # Realistic phishing URLs - various attack patterns
        phishing_urls = [
            # Typosquatting attacks
            "http://paypa1-secure.com/login",
            "http://amaz0n-verify.com/account",
            "http://g00gle-security.com/signin",
            "http://micros0ft-support.com/verify",
            "http://faceb00k-login.com/auth",
            "http://app1e-id.com/signin",
            "http://netf1ix-billing.com/update",
            "http://1nstagram-verify.com/login",
            "http://linkedln-security.com/auth",
            "http://tw1tter-verify.com/login",
            "http://dr0pbox-share.com/file",
            "http://chasse-bank.com/login",
            "http://we11sfargo-secure.com/signin",
            "http://c1tibank-verify.com/auth",
            "http://stearn-community.com/login",
            "http://3bay-secure.com/signin",
            # Brand in subdomain attacks
            "http://paypal.secure-login.malicious.com/",
            "http://amazon.account-verify.evil.net/",
            "http://google.signin-secure.phish.org/",
            "http://microsoft.support-ticket.bad.com/",
            "http://apple.icloud-verify.fake.net/",
            "http://facebook.security-check.scam.com/",
            "http://netflix.billing-update.fraud.net/",
            "http://chase.secure-banking.evil.com/",
            "http://wellsfargo.account-alert.bad.net/",
            "http://bankofamerica.verify-identity.scam.org/",
            # IP address attacks
            "http://192.168.1.100/paypal/login.php",
            "http://10.0.0.1/amazon/verify.html",
            "http://172.16.0.1:8080/microsoft/auth",
            "http://123.45.67.89/google/signin",
            "http://98.76.54.32/apple/icloud",
            # Long obfuscated URLs
            "http://secure-paypal-login-verification-account-update.malicious-domain.com/signin.php?user=victim&token=abc123",
            "http://amazon-prime-membership-renewal-required-immediate-action.scam.net/verify.html",
            "http://microsoft-account-suspended-unusual-activity-detected-verify-now.phish.org/auth",
            "http://your-apple-id-has-been-locked-verify-identity-to-unlock.fraud.com/verify",
            "http://netflix-payment-declined-update-billing-information-immediately.evil.net/update",
            # Suspicious keywords
            "http://secure-login-paypal.com/verify",
            "http://account-verify-amazon.net/update",
            "http://signin-google-secure.org/auth",
            "http://password-reset-microsoft.com/recover",
            "http://confirm-identity-apple.net/verify",
            "http://urgent-security-facebook.com/alert",
            "http://update-payment-netflix.org/billing",
            "http://verify-account-chase.com/secure",
            "http://confirm-transaction-paypal.net/auth",
            "http://security-alert-bankofamerica.org/verify",
            # URL shortener abuse
            "http://bit.ly/3abc123-paypal-login",
            "http://tinyurl.com/amazon-verify-now",
            "http://t.co/microsoft-urgent",
            "http://goo.gl/apple-verify",
            # Homograph attacks (mixed characters)
            "http://pаypal.com/login",  # Cyrillic 'а'
            "http://аmazon.com/verify",  # Cyrillic 'а'
            "http://gооgle.com/signin",  # Cyrillic 'о'
            "http://micrоsoft.com/auth",  # Cyrillic 'о'
            # Suspicious TLDs
            "http://paypal-login.xyz/signin",
            "http://amazon-verify.tk/account",
            "http://google-secure.ml/auth",
            "http://microsoft-support.cf/help",
            "http://apple-verify.ga/icloud",
            # @ symbol attacks
            "http://legitimate.com@malicious.com/phish",
            "http://paypal.com@evil.net/login",
            "http://amazon.com@scam.org/verify",
            # Double slash redirect
            "http://malicious.com//https://paypal.com/login",
            "http://evil.net//amazon.com/account",
            # Random string domains (likely generated)
            "http://xk7jf9s.com/paypal/login",
            "http://a8b2c4d.net/amazon/verify",
            "http://zxy123abc.org/microsoft/auth",
            "http://qwerty789.tk/google/signin",
            # Excessive subdomains
            "http://login.secure.verify.paypal.malicious.com/signin",
            "http://account.update.confirm.amazon.evil.net/verify",
            "http://auth.security.check.google.scam.org/signin",
            # HTTP on sensitive pages
            "http://paypal.com.malicious.net/login",
            "http://amazon.com.evil.org/account",
            "http://banking.chase.phish.com/signin",
            # Path-based attacks
            "http://malicious.com/paypal/login.php",
            "http://evil.net/amazon/verify-account.html",
            "http://scam.org/microsoft/password-reset.asp",
            "http://phish.com/google/2fa-setup.php",
            "http://fraud.net/apple/icloud-locked.html",
        ]

        # Extract features from actual URLs
        X = []
        y = []

        # Process legitimate URLs
        for url in legitimate_urls:
            try:
                feature_vector, _ = url_analyzer.get_feature_vector(url)
                X.append(feature_vector)
                y.append(0)  # Legitimate
            except Exception:
                pass

        # Process phishing URLs
        for url in phishing_urls:
            try:
                feature_vector, _ = url_analyzer.get_feature_vector(url)
                X.append(feature_vector)
                y.append(1)  # Phishing
            except Exception:
                pass

        # Add augmented data to improve model robustness
        np.random.seed(42)
        X_augmented = []
        y_augmented = []

        # Generate variations of legitimate URL features
        for _ in range(200):
            features = [
                np.random.randint(15, 80),   # url_length - moderate
                np.random.randint(5, 25),    # domain_length - moderate
                np.random.randint(0, 15),    # subdomain_length
                np.random.randint(0, 40),    # path_length
                np.random.randint(0, 30),    # query_length
                np.random.randint(1, 4),     # num_dots - few
                np.random.randint(0, 2),     # num_hyphens - few
                np.random.randint(0, 1),     # num_underscores - rare
                np.random.randint(2, 5),     # num_slashes
                0,                            # num_at_symbols - none
                np.random.randint(0, 8),     # num_digits - few
                np.random.randint(0, 3),     # num_special_chars - few
                0,                            # has_ip - no
                1,                            # has_https - yes (90% of legit)
                0,                            # has_port - no
                0,                            # has_at_symbol - no
                np.random.uniform(2.8, 4.2), # entropy - moderate
                np.random.uniform(0.02, 0.18), # digit_ratio - low
                np.random.uniform(0.55, 0.85), # letter_ratio - high
                0,                            # suspicious_tld - no
                np.random.randint(0, 2),     # subdomain_count - few
                0,                            # num_suspicious_keywords - none
                0,                            # is_shortened - no
                0,                            # has_brand_in_subdomain - no
                0,                            # excessive_subdomains - no
                0,                            # long_domain - no
            ]
            X_augmented.append(features)
            y_augmented.append(0)

        # Generate variations of phishing URL features
        for _ in range(200):
            features = [
                np.random.randint(40, 200),  # url_length - longer
                np.random.randint(12, 50),   # domain_length - longer
                np.random.randint(5, 40),    # subdomain_length - longer
                np.random.randint(10, 100),  # path_length - longer
                np.random.randint(5, 60),    # query_length - longer
                np.random.randint(2, 8),     # num_dots - more
                np.random.randint(1, 6),     # num_hyphens - more
                np.random.randint(0, 4),     # num_underscores - more
                np.random.randint(3, 10),    # num_slashes - more
                np.random.choice([0, 1], p=[0.85, 0.15]),  # num_at_symbols
                np.random.randint(3, 20),    # num_digits - more
                np.random.randint(2, 12),    # num_special_chars - more
                np.random.choice([0, 1], p=[0.85, 0.15]),  # has_ip
                np.random.choice([0, 1], p=[0.6, 0.4]),    # has_https - often missing
                np.random.choice([0, 1], p=[0.92, 0.08]),  # has_port
                np.random.choice([0, 1], p=[0.88, 0.12]),  # has_at_symbol
                np.random.uniform(3.8, 5.8), # entropy - higher
                np.random.uniform(0.08, 0.30), # digit_ratio - higher
                np.random.uniform(0.35, 0.65), # letter_ratio - lower
                np.random.choice([0, 1], p=[0.4, 0.6]),  # suspicious_tld - often
                np.random.randint(1, 6),     # subdomain_count - more
                np.random.randint(1, 5),     # num_suspicious_keywords - present
                np.random.choice([0, 1], p=[0.75, 0.25]),  # is_shortened
                np.random.choice([0, 1], p=[0.5, 0.5]),    # has_brand_in_subdomain
                np.random.choice([0, 1], p=[0.55, 0.45]),  # excessive_subdomains
                np.random.choice([0, 1], p=[0.45, 0.55]),  # long_domain
            ]
            X_augmented.append(features)
            y_augmented.append(1)

        # Combine real URL features with augmented data
        X = np.array(X + X_augmented)
        y = np.array(y + y_augmented)

        # Train model with optimized parameters
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        self.model = RandomForestClassifier(
            n_estimators=150,
            max_depth=12,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1,
            class_weight='balanced'
        )
        self.model.fit(X_scaled, y)
        self.is_loaded = True

        # Save the model
        self.save_model()

    def save_model(self):
        """Save trained model to disk."""
        try:
            os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
            joblib.dump({
                'model': self.model,
                'scaler': self.scaler
            }, self.model_path)
        except Exception as e:
            print(f"Error saving model: {e}")

    def _is_known_legitimate(self, url: str) -> bool:
        """Check if URL belongs to a known legitimate domain."""
        try:
            extracted = tldextract.extract(url)
            domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain
            full_domain = f"{extracted.subdomain}.{domain}" if extracted.subdomain else domain

            # Check if the registered domain is in our known list
            if domain.lower() in self.KNOWN_LEGITIMATE_DOMAINS:
                return True
            if full_domain.lower() in self.KNOWN_LEGITIMATE_DOMAINS:
                return True

            return False
        except Exception:
            return False

    def predict(self, url: str) -> Dict[str, Any]:
        """Predict if URL is phishing."""
        if not self.is_loaded or self.model is None:
            self._initialize_default_model()

        # Extract features
        feature_vector, raw_features = url_analyzer.get_feature_vector(url)

        # Scale features
        X = np.array([feature_vector])
        X_scaled = self.scaler.transform(X)

        # Get prediction and probability
        prediction = self.model.predict(X_scaled)[0]
        probabilities = self.model.predict_proba(X_scaled)[0]

        phishing_probability = probabilities[1]

        # Check if this is a known legitimate domain
        # If so, significantly reduce the ML score to prevent false positives
        is_known_legit = self._is_known_legitimate(url)
        if is_known_legit:
            # Known legitimate domains should have very low ML scores
            phishing_probability = min(phishing_probability * 0.1, 0.15)

        is_phishing = phishing_probability >= self.threshold

        # Get feature importance
        feature_importance = dict(zip(
            self.feature_names,
            [round(imp, 4) for imp in self.model.feature_importances_]
        ))

        # Get top contributing features
        sorted_importance = sorted(
            feature_importance.items(),
            key=lambda x: x[1],
            reverse=True
        )[:5]

        return {
            'is_phishing': bool(is_phishing),
            'ml_score': round(float(phishing_probability), 4),
            'confidence': round(float(max(probabilities)), 4),
            'threshold': self.threshold,
            'top_features': sorted_importance,
            'feature_vector': feature_vector,
            'raw_features': raw_features,
            'is_known_legitimate': is_known_legit
        }

    def train(self, urls: list, labels: list) -> Dict[str, float]:
        """Train model on new data."""
        # Extract features from URLs
        X = []
        for url in urls:
            feature_vector, _ = url_analyzer.get_feature_vector(url)
            X.append(feature_vector)

        X = np.array(X)
        y = np.array(labels)

        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42
        )

        # Scale features
        self.scaler = StandardScaler()
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)

        # Train model
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            n_jobs=-1
        )
        self.model.fit(X_train_scaled, y_train)

        # Evaluate
        train_score = self.model.score(X_train_scaled, y_train)
        test_score = self.model.score(X_test_scaled, y_test)

        # Save model
        self.save_model()
        self.is_loaded = True

        return {
            'train_accuracy': round(train_score, 4),
            'test_accuracy': round(test_score, 4),
            'samples_trained': len(X_train),
            'samples_tested': len(X_test)
        }


# Singleton instance
ml_detector = PhishingMLDetector()
