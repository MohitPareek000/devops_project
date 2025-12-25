import os
import numpy as np
from typing import Dict, Any, Tuple, Optional
import joblib
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from app.core.config import settings
from .url_analyzer import url_analyzer


class PhishingMLDetector:
    """Machine Learning based phishing URL detector."""

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
                data = joblib.load(self.model_path)
                self.model = data['model']
                self.scaler = data['scaler']
                self.is_loaded = True
                return True
        except Exception as e:
            print(f"Error loading model: {e}")

        # Initialize with default model if not found
        self._initialize_default_model()
        return False

    def _initialize_default_model(self):
        """Initialize a default model with synthetic training data."""
        # Generate synthetic training data based on known patterns
        np.random.seed(42)
        n_samples = 1000

        # Generate legitimate URL features
        legit_features = []
        for _ in range(n_samples // 2):
            features = [
                np.random.randint(20, 60),   # url_length
                np.random.randint(5, 20),    # domain_length
                np.random.randint(0, 10),    # subdomain_length
                np.random.randint(0, 30),    # path_length
                np.random.randint(0, 20),    # query_length
                np.random.randint(1, 4),     # num_dots
                np.random.randint(0, 2),     # num_hyphens
                np.random.randint(0, 1),     # num_underscores
                np.random.randint(2, 5),     # num_slashes
                0,                            # num_at_symbols
                np.random.randint(0, 5),     # num_digits
                np.random.randint(0, 3),     # num_special_chars
                0,                            # has_ip
                np.random.choice([0, 1], p=[0.1, 0.9]),  # has_https
                0,                            # has_port
                0,                            # has_at_symbol
                np.random.uniform(3.0, 4.0), # entropy
                np.random.uniform(0.05, 0.15), # digit_ratio
                np.random.uniform(0.6, 0.8), # letter_ratio
                0,                            # suspicious_tld
                np.random.randint(0, 2),     # subdomain_count
                0,                            # num_suspicious_keywords
                0,                            # is_shortened
                0,                            # has_brand_in_subdomain
                0,                            # excessive_subdomains
                0,                            # long_domain
            ]
            legit_features.append(features)

        # Generate phishing URL features
        phish_features = []
        for _ in range(n_samples // 2):
            features = [
                np.random.randint(50, 150),  # url_length (longer)
                np.random.randint(15, 40),   # domain_length (longer)
                np.random.randint(10, 30),   # subdomain_length (longer)
                np.random.randint(20, 80),   # path_length (longer)
                np.random.randint(10, 50),   # query_length (longer)
                np.random.randint(3, 8),     # num_dots (more)
                np.random.randint(1, 5),     # num_hyphens (more)
                np.random.randint(0, 3),     # num_underscores
                np.random.randint(3, 8),     # num_slashes (more)
                np.random.choice([0, 1], p=[0.8, 0.2]),  # num_at_symbols
                np.random.randint(5, 15),    # num_digits (more)
                np.random.randint(3, 10),    # num_special_chars (more)
                np.random.choice([0, 1], p=[0.8, 0.2]),  # has_ip
                np.random.choice([0, 1], p=[0.4, 0.6]),  # has_https
                np.random.choice([0, 1], p=[0.9, 0.1]),  # has_port
                np.random.choice([0, 1], p=[0.85, 0.15]), # has_at_symbol
                np.random.uniform(4.0, 5.5), # entropy (higher)
                np.random.uniform(0.1, 0.25), # digit_ratio (higher)
                np.random.uniform(0.4, 0.6), # letter_ratio (lower)
                np.random.choice([0, 1], p=[0.5, 0.5]),  # suspicious_tld
                np.random.randint(2, 5),     # subdomain_count (more)
                np.random.randint(1, 4),     # num_suspicious_keywords
                np.random.choice([0, 1], p=[0.7, 0.3]),  # is_shortened
                np.random.choice([0, 1], p=[0.6, 0.4]),  # has_brand_in_subdomain
                np.random.choice([0, 1], p=[0.6, 0.4]),  # excessive_subdomains
                np.random.choice([0, 1], p=[0.5, 0.5]),  # long_domain
            ]
            phish_features.append(features)

        # Combine data
        X = np.array(legit_features + phish_features)
        y = np.array([0] * len(legit_features) + [1] * len(phish_features))

        # Train model
        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            random_state=42,
            n_jobs=-1
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
            'raw_features': raw_features
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
