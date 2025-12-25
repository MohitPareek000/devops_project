"""
Training script for phishing URL detection model using Kaggle datasets.

Usage:
    python train_from_dataset.py --dataset <dataset_name>

Supported datasets:
    - phiusiil: PhiUSIIL Phishing URL Dataset (recommended, 235k+ URLs)
    - kaggle-phishing: Phishing Site URLs dataset
    - local: Use local CSV file
"""

import os
import sys
import argparse
import pickle
import pandas as pd
import numpy as np
from pathlib import Path
from typing import Tuple, List
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.preprocessing import StandardScaler

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.services.url_analyzer import URLAnalyzer


class PhishingModelTrainer:
    """Train phishing detection model from URL datasets."""

    def __init__(self, model_path: str = None):
        self.url_analyzer = URLAnalyzer()
        self.model_path = model_path or str(Path(__file__).parent / "model.pkl")
        self.scaler = StandardScaler()
        self.model = None

    def extract_features_from_url(self, url: str) -> List[float]:
        """Extract feature vector from a single URL."""
        try:
            vector, _ = self.url_analyzer.get_feature_vector(url)
            return vector
        except Exception as e:
            # Return zeros on error
            return [0.0] * 26

    def load_phiusiil_dataset(self, filepath: str) -> Tuple[List[str], List[int]]:
        """Load PhiUSIIL dataset format."""
        print(f"Loading PhiUSIIL dataset from {filepath}...")
        df = pd.read_csv(filepath)

        # PhiUSIIL has 'URL' and 'label' columns (0=legitimate, 1=phishing)
        if 'URL' in df.columns and 'label' in df.columns:
            urls = df['URL'].tolist()
            labels = df['label'].tolist()
        elif 'url' in df.columns and 'label' in df.columns:
            urls = df['url'].tolist()
            labels = df['label'].tolist()
        else:
            raise ValueError(f"Unknown dataset format. Columns: {df.columns.tolist()}")

        print(f"Loaded {len(urls)} URLs ({sum(labels)} phishing, {len(labels) - sum(labels)} legitimate)")
        return urls, labels

    def load_kaggle_phishing_dataset(self, filepath: str) -> Tuple[List[str], List[int]]:
        """Load Kaggle Phishing Site URLs dataset format."""
        print(f"Loading Kaggle phishing dataset from {filepath}...")
        df = pd.read_csv(filepath)

        # Common formats: 'URL'/'url' column with 'Label'/'label'/'status' column
        url_col = None
        label_col = None

        for col in ['URL', 'url', 'urls']:
            if col in df.columns:
                url_col = col
                break

        for col in ['Label', 'label', 'status', 'type', 'result']:
            if col in df.columns:
                label_col = col
                break

        if not url_col or not label_col:
            raise ValueError(f"Could not identify URL and label columns. Columns: {df.columns.tolist()}")

        urls = df[url_col].tolist()

        # Convert labels to binary (1=phishing, 0=legitimate)
        raw_labels = df[label_col].tolist()
        labels = []
        for label in raw_labels:
            if isinstance(label, str):
                label_lower = label.lower()
                if label_lower in ['phishing', 'bad', 'malicious', '1', 'yes']:
                    labels.append(1)
                else:
                    labels.append(0)
            else:
                labels.append(int(label))

        print(f"Loaded {len(urls)} URLs ({sum(labels)} phishing, {len(labels) - sum(labels)} legitimate)")
        return urls, labels

    def load_generic_csv(self, filepath: str) -> Tuple[List[str], List[int]]:
        """Load any CSV with URL and label columns."""
        print(f"Loading CSV from {filepath}...")
        df = pd.read_csv(filepath)

        print(f"Available columns: {df.columns.tolist()}")

        # Try to find URL column
        url_col = None
        for col in df.columns:
            if 'url' in col.lower():
                url_col = col
                break

        if not url_col:
            url_col = df.columns[0]
            print(f"Using first column as URL: {url_col}")

        # Try to find label column
        label_col = None
        for col in df.columns:
            col_lower = col.lower()
            if col_lower in ['label', 'status', 'type', 'class', 'result', 'phishing']:
                label_col = col
                break

        if not label_col:
            label_col = df.columns[-1]
            print(f"Using last column as label: {label_col}")

        urls = df[url_col].dropna().tolist()
        raw_labels = df[label_col].dropna().tolist()

        # Convert labels
        labels = []
        for label in raw_labels:
            if isinstance(label, str):
                label_lower = label.lower().strip()
                if label_lower in ['phishing', 'bad', 'malicious', '1', 'yes', 'phish']:
                    labels.append(1)
                elif label_lower in ['legitimate', 'good', 'benign', '0', 'no', 'safe']:
                    labels.append(0)
                else:
                    # Try to interpret as number
                    try:
                        labels.append(int(float(label)))
                    except:
                        labels.append(0)
            else:
                labels.append(int(label))

        # Ensure same length
        min_len = min(len(urls), len(labels))
        urls = urls[:min_len]
        labels = labels[:min_len]

        print(f"Loaded {len(urls)} URLs ({sum(labels)} phishing, {len(labels) - sum(labels)} legitimate)")
        return urls, labels

    def prepare_dataset(self, urls: List[str], labels: List[int],
                       max_samples: int = None, balance: bool = True) -> Tuple[np.ndarray, np.ndarray]:
        """Extract features and prepare dataset for training."""
        print("Extracting features from URLs...")

        # Optionally limit samples for faster training
        if max_samples and len(urls) > max_samples:
            if balance:
                # Balance by selecting equal numbers of each class
                phishing_idx = [i for i, l in enumerate(labels) if l == 1]
                legit_idx = [i for i, l in enumerate(labels) if l == 0]

                n_per_class = min(max_samples // 2, len(phishing_idx), len(legit_idx))

                np.random.seed(42)
                selected_phishing = np.random.choice(phishing_idx, n_per_class, replace=False)
                selected_legit = np.random.choice(legit_idx, n_per_class, replace=False)

                selected_idx = list(selected_phishing) + list(selected_legit)
                urls = [urls[i] for i in selected_idx]
                labels = [labels[i] for i in selected_idx]
            else:
                urls = urls[:max_samples]
                labels = labels[:max_samples]

        features = []
        valid_labels = []

        for i, (url, label) in enumerate(zip(urls, labels)):
            if i % 1000 == 0:
                print(f"Processing {i}/{len(urls)} URLs...")

            try:
                if not isinstance(url, str) or len(url) < 5:
                    continue

                vector = self.extract_features_from_url(url)
                features.append(vector)
                valid_labels.append(label)
            except Exception as e:
                continue

        print(f"Successfully extracted features from {len(features)} URLs")

        X = np.array(features)
        y = np.array(valid_labels)

        return X, y

    def train(self, X: np.ndarray, y: np.ndarray, test_size: float = 0.2) -> dict:
        """Train the model and return metrics."""
        print(f"\nTraining model on {len(X)} samples...")
        print(f"Class distribution: {sum(y)} phishing, {len(y) - sum(y)} legitimate")

        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )

        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)

        # Train RandomForest
        print("\nTraining RandomForest classifier...")
        self.model = RandomForestClassifier(
            n_estimators=200,
            max_depth=15,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1,
            class_weight='balanced'
        )
        self.model.fit(X_train_scaled, y_train)

        # Evaluate
        y_pred = self.model.predict(X_test_scaled)
        y_prob = self.model.predict_proba(X_test_scaled)[:, 1]

        accuracy = accuracy_score(y_test, y_pred)

        print(f"\n{'='*50}")
        print("MODEL EVALUATION RESULTS")
        print(f"{'='*50}")
        print(f"\nAccuracy: {accuracy:.4f}")
        print(f"\nClassification Report:")
        print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
        print(f"\nConfusion Matrix:")
        print(confusion_matrix(y_test, y_pred))

        # Feature importances
        feature_names = [
            'url_length', 'domain_length', 'subdomain_length', 'path_length',
            'query_length', 'num_dots', 'num_hyphens', 'num_underscores',
            'num_slashes', 'num_at_symbols', 'num_digits', 'num_special_chars',
            'has_ip', 'has_https', 'has_port', 'has_at_symbol', 'entropy',
            'digit_ratio', 'letter_ratio', 'suspicious_tld', 'subdomain_count',
            'num_suspicious_keywords', 'is_shortened', 'has_brand_in_subdomain',
            'excessive_subdomains', 'long_domain'
        ]

        importances = self.model.feature_importances_
        sorted_idx = np.argsort(importances)[::-1]

        print(f"\nTop 10 Feature Importances:")
        for i in range(min(10, len(feature_names))):
            idx = sorted_idx[i]
            print(f"  {feature_names[idx]}: {importances[idx]:.4f}")

        return {
            'accuracy': accuracy,
            'classification_report': classification_report(y_test, y_pred, output_dict=True),
            'confusion_matrix': confusion_matrix(y_test, y_pred).tolist(),
            'n_train': len(X_train),
            'n_test': len(X_test)
        }

    def save_model(self):
        """Save trained model and scaler."""
        print(f"\nSaving model to {self.model_path}...")

        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'feature_names': [
                'url_length', 'domain_length', 'subdomain_length', 'path_length',
                'query_length', 'num_dots', 'num_hyphens', 'num_underscores',
                'num_slashes', 'num_at_symbols', 'num_digits', 'num_special_chars',
                'has_ip', 'has_https', 'has_port', 'has_at_symbol', 'entropy',
                'digit_ratio', 'letter_ratio', 'suspicious_tld', 'subdomain_count',
                'num_suspicious_keywords', 'is_shortened', 'has_brand_in_subdomain',
                'excessive_subdomains', 'long_domain'
            ]
        }

        with open(self.model_path, 'wb') as f:
            pickle.dump(model_data, f)

        print(f"Model saved successfully!")

    def test_urls(self, urls: List[str]):
        """Test the model on specific URLs."""
        print(f"\n{'='*50}")
        print("TESTING SPECIFIC URLs")
        print(f"{'='*50}")

        for url in urls:
            features = self.extract_features_from_url(url)
            features_scaled = self.scaler.transform([features])

            prob = self.model.predict_proba(features_scaled)[0][1]
            prediction = "PHISHING" if prob >= 0.5 else "LEGITIMATE"

            print(f"\n  URL: {url}")
            print(f"  Prediction: {prediction} ({prob:.2%} confidence)")


def download_dataset():
    """Download a sample phishing dataset if none exists."""
    dataset_dir = Path(__file__).parent / "datasets"
    dataset_dir.mkdir(exist_ok=True)

    sample_file = dataset_dir / "sample_phishing_urls.csv"

    if sample_file.exists():
        return str(sample_file)

    print("Creating sample dataset...")

    # Create a substantial sample dataset with realistic URLs
    legitimate_urls = [
        "https://www.google.com/search?q=weather",
        "https://www.amazon.com/dp/B08N5WRWNW",
        "https://github.com/microsoft/vscode",
        "https://stackoverflow.com/questions/tagged/python",
        "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
        "https://www.linkedin.com/in/example-profile",
        "https://www.facebook.com/settings",
        "https://twitter.com/home",
        "https://www.instagram.com/explore",
        "https://www.reddit.com/r/programming",
        "https://www.netflix.com/browse",
        "https://www.spotify.com/account/overview",
        "https://www.apple.com/shop/buy-iphone",
        "https://www.microsoft.com/en-us/windows",
        "https://www.dropbox.com/home",
        "https://mail.google.com/mail/u/0/#inbox",
        "https://www.paypal.com/myaccount/home",
        "https://www.ebay.com/myb/ActiveBids",
        "https://www.walmart.com/cart",
        "https://www.target.com/",
        "https://www.bestbuy.com/site/computer-accessories",
        "https://www.nytimes.com/section/world",
        "https://www.bbc.com/news",
        "https://www.cnn.com/politics",
        "https://www.weather.com/weather/today",
        "https://www.wikipedia.org/wiki/Main_Page",
        "https://docs.python.org/3/library/",
        "https://reactjs.org/docs/getting-started.html",
        "https://nodejs.org/en/download/",
        "https://www.npmjs.com/package/express",
        "https://pypi.org/project/requests/",
        "https://www.kaggle.com/datasets",
        "https://www.coursera.org/learn/machine-learning",
        "https://www.udemy.com/courses/development/",
        "https://www.medium.com/@username",
        "https://www.quora.com/",
        "https://www.pinterest.com/ideas/",
        "https://www.tumblr.com/dashboard",
        "https://www.twitch.tv/directory",
        "https://discord.com/channels/@me",
        "https://slack.com/signin",
        "https://zoom.us/join",
        "https://meet.google.com/",
        "https://www.skype.com/en/",
        "https://outlook.live.com/mail/0/inbox",
        "https://www.icloud.com/mail",
        "https://www.chase.com/personal/checking",
        "https://www.bankofamerica.com/",
        "https://www.wellsfargo.com/",
        "https://www.capitalone.com/",
    ]

    phishing_urls = [
        # Typosquatting
        "http://paypa1-secure.com/login",
        "http://amaz0n-verify.com/account",
        "http://faceb00k-security.com/confirm",
        "http://g00gle-support.com/verify",
        "http://micr0soft-update.com/windows",
        "http://app1e-id.com/verify",
        "http://netf1ix-billing.com/update",
        "http://linkedln-security.com/signin",
        "http://tw1tter-verify.com/account",
        "http://1nstagram-help.com/support",

        # Brand in subdomain
        "http://paypal.secure-login.malicious.com/signin",
        "http://amazon.verify-account.phishing.net/update",
        "http://facebook.security-check.bad.org/confirm",
        "http://google.support-team.evil.com/help",
        "http://microsoft.update-center.fake.net/download",
        "http://apple.id-verify.scam.com/account",
        "http://netflix.billing-update.fraud.net/payment",
        "http://bank.secure-login.phish.com/account",

        # IP addresses
        "http://192.168.1.1/paypal/login.html",
        "http://10.0.0.1/amazon/signin.php",
        "http://172.16.0.1/facebook/verify.html",
        "http://45.67.89.123/banking/secure/login",
        "http://123.45.67.89/account/verify/paypal",

        # Suspicious TLDs with brands
        "http://paypal-secure.xyz/login",
        "http://amazon-verify.tk/account",
        "http://google-support.ml/help",
        "http://facebook-security.ga/check",
        "http://microsoft-update.cf/download",

        # Random string domains
        "http://abc123xyz789.com/paypal/login",
        "http://qwerty12345.net/amazon/verify",
        "http://xyzabc987.org/google/signin",
        "http://random123abc.tk/facebook/security",

        # Long suspicious URLs
        "http://secure-paypal-account-verification-update-login-confirm.com/signin",
        "http://amazon-order-confirmation-verify-account-security.net/update",
        "http://facebook-security-check-verify-identity-confirm.org/login",

        # Multiple hyphens
        "http://pay-pal-secure-login-verify.com/account",
        "http://amazon-prime-account-update-verify.net/signin",
        "http://google-account-security-verify-update.org/check",

        # Suspicious paths
        "http://suspicious-site.com/wp-admin/paypal/login.php",
        "http://evil-domain.net/.hidden/amazon/verify.html",
        "http://phishing-site.org/cgi-bin/facebook/security.php",
        "http://malicious.com/admin/login/banking/secure",

        # URL shorteners with suspicious content
        "http://bit.ly/paypal-verify-2024",
        "http://tinyurl.com/amazon-security",
        "http://t.co/google-support",

        # Encoded characters
        "http://paypal%2Dsecure.com/login",
        "http://amazon%2Everify.net/account",

        # HTTP on sensitive pages
        "http://banking-secure.com/login/account",
        "http://creditcard-verify.net/update/payment",
        "http://password-reset.org/account/recover",

        # Unicode/homograph attacks
        "http://pаypal.com/login",  # Cyrillic 'а'
        "http://аmazon.com/signin",  # Cyrillic 'а'

        # Double extensions
        "http://document.pdf.exe.malicious.com/download",
        "http://invoice.doc.js.evil.net/open",

        # Excessive subdomains
        "http://secure.login.verify.update.confirm.paypal.evil.com/signin",
        "http://account.security.check.verify.amazon.phish.net/update",

        # Urgent/scam keywords
        "http://urgent-verify-account-suspended.com/paypal/login",
        "http://winner-prize-claim-now.net/amazon/reward",
        "http://account-locked-verify-immediately.org/banking",
        "http://security-alert-unusual-activity.com/facebook/check",

        # Credential harvesting patterns
        "http://login-secure-verify.com/credentials/update",
        "http://password-reset-urgent.net/account/recover",
        "http://credit-card-update-required.org/payment/verify",

        # More sophisticated phishing
        "http://secure.account-paypal.com/webapps/auth/signin",
        "http://my-amazon.orders-tracking.net/gp/css/account",
        "http://login.microsoft-365.support-team.com/oauth2/authorize",
        "http://appleid.apple.verify-account.support.com/account",
    ]

    # Create DataFrame
    data = []
    for url in legitimate_urls:
        data.append({'url': url, 'label': 0})
    for url in phishing_urls:
        data.append({'url': url, 'label': 1})

    df = pd.DataFrame(data)
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)  # Shuffle
    df.to_csv(sample_file, index=False)

    print(f"Created sample dataset with {len(legitimate_urls)} legitimate and {len(phishing_urls)} phishing URLs")
    return str(sample_file)


def main():
    parser = argparse.ArgumentParser(description='Train phishing detection model')
    parser.add_argument('--dataset', type=str, default='sample',
                       help='Dataset to use: sample, phiusiil, kaggle, or path to CSV file')
    parser.add_argument('--max-samples', type=int, default=50000,
                       help='Maximum samples to use for training')
    parser.add_argument('--output', type=str, default=None,
                       help='Output path for model file')

    args = parser.parse_args()

    trainer = PhishingModelTrainer(model_path=args.output)

    # Load dataset
    if args.dataset == 'sample':
        filepath = download_dataset()
        urls, labels = trainer.load_generic_csv(filepath)
    elif os.path.isfile(args.dataset):
        urls, labels = trainer.load_generic_csv(args.dataset)
    else:
        print(f"Dataset not found: {args.dataset}")
        print("\nTo use a Kaggle dataset:")
        print("1. Download from https://www.kaggle.com/datasets/taruntiwarihp/phishing-site-urls")
        print("2. Extract the CSV file")
        print("3. Run: python train_from_dataset.py --dataset /path/to/phishing_urls.csv")
        print("\nUsing sample dataset instead...")
        filepath = download_dataset()
        urls, labels = trainer.load_generic_csv(filepath)

    # Prepare and train
    X, y = trainer.prepare_dataset(urls, labels, max_samples=args.max_samples)
    trainer.train(X, y)
    trainer.save_model()

    # Test on specific URLs
    test_urls = [
        "https://www.google.com/search?q=python",
        "https://www.amazon.com/dp/B08N5WRWNW",
        "http://paypa1-secure.com/login",
        "http://amaz0n-verify.com/account",
        "http://faceb00k-security.com/confirm",
        "http://192.168.1.1/paypal/login.html",
        "http://paypal.secure-login.malicious.com/signin",
        "http://secure-paypal-account-verification.com/signin",
    ]
    trainer.test_urls(test_urls)

    print(f"\n{'='*50}")
    print("TRAINING COMPLETE!")
    print(f"{'='*50}")
    print(f"\nModel saved to: {trainer.model_path}")
    print("\nTo use this model, restart the backend server.")


if __name__ == "__main__":
    main()
