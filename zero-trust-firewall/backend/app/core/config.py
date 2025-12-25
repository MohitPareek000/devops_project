from pydantic_settings import BaseSettings
from typing import List
import secrets


class Settings(BaseSettings):
    # Application
    APP_NAME: str = "Zero Trust Firewall"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False

    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8000

    # Database (SQLite for local dev, PostgreSQL for production)
    DATABASE_URL: str = "sqlite:///./zerotrust.db"

    # Security
    SECRET_KEY: str = secrets.token_urlsafe(32)
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # CORS
    CORS_ORIGINS: List[str] = ["http://localhost:3000", "http://localhost:5173"]

    # Rate Limiting
    RATE_LIMIT_PER_MINUTE: int = 60

    # ML Model
    ML_MODEL_PATH: str = "app/ml/model.pkl"
    ML_THRESHOLD: float = 0.5

    # Threat Intelligence
    PHISHING_BLACKLIST_URL: str = "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt"

    # Email (for alerts)
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    EMAIL_FROM: str = "alerts@zerotrust.local"

    # WebSocket
    WS_HEARTBEAT_INTERVAL: int = 30

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()
