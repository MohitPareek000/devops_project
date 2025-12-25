# Zero Trust Firewall with Phishing URL Inspection

A comprehensive security solution implementing Zero Trust architecture with ML-powered phishing URL detection, real-time network monitoring, and an intuitive security dashboard.

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Architecture](#architecture)
- [Technology Stack](#technology-stack)
- [Installation](#installation)
- [Running the Application](#running-the-application)
- [User Guide](#user-guide)
- [API Documentation](#api-documentation)
- [Security Features](#security-features)
- [Configuration](#configuration)
- [Troubleshooting](#troubleshooting)

---

## Overview

Zero Trust Firewall is a modern security platform that operates on the principle of "never trust, always verify." It combines machine learning-based phishing detection with rule-based analysis to provide comprehensive URL threat assessment.

### Key Capabilities

- **ML-Powered Phishing Detection**: Uses Random Forest classifier with 26+ URL features
- **Rule-Based Analysis**: 12 detection rules including homograph attacks, typosquatting
- **Real-Time Monitoring**: Live network traffic visualization and threat alerts
- **Zero Trust Architecture**: JWT authentication, RBAC, session management

---

## Features

### 1. URL Scanner
Scan URLs for phishing threats using hybrid ML + rule-based detection.

- Single URL scanning
- Batch URL scanning (up to 100 URLs)
- Detailed threat analysis with confidence scores
- Feature extraction visualization

### 2. Dashboard
Real-time security overview with:

- Threat statistics (total scans, detections, blocked threats)
- Severity distribution charts
- Threat trend analysis
- Top blocked domains
- Recent threat activity

### 3. Threat Log
Comprehensive scan history with:

- Filterable results by status, severity, date
- Detailed scan reports
- Export capabilities
- Pagination support

### 4. Network Monitor
Live network traffic analysis:

- Connection tracking
- Bandwidth monitoring
- Protocol distribution
- Geographic visualization
- Real-time updates via WebSocket

### 5. Alerts System
Security alert management:

- Severity-based notifications
- Read/acknowledge workflow
- Alert metadata and context
- Unread count indicators

### 6. User Management
Role-based access control:

- **Admin**: Full system access
- **Analyst**: View and analyze threats
- **Viewer**: Read-only dashboard access

---

## Architecture

```
+-------------------+     +-------------------+     +-------------------+
|                   |     |                   |     |                   |
|    React Frontend |---->|   FastAPI Backend |---->|   PostgreSQL/     |
|    (Port 3000)    |     |   (Port 8000)     |     |   SQLite DB       |
|                   |     |                   |     |                   |
+-------------------+     +-------------------+     +-------------------+
                                   |
                                   v
                          +-------------------+
                          |                   |
                          |   ML Detection    |
                          |   Engine          |
                          |                   |
                          +-------------------+
```

### Component Overview

| Component | Description |
|-----------|-------------|
| Frontend | React 18 + TypeScript + TailwindCSS |
| Backend | FastAPI + SQLAlchemy + Pydantic |
| ML Engine | Scikit-learn Random Forest Classifier |
| Database | SQLite (dev) / PostgreSQL (prod) |
| Auth | JWT tokens with refresh mechanism |

---

## Technology Stack

### Backend
- **Python 3.9+**
- **FastAPI** - High-performance async web framework
- **SQLAlchemy** - ORM for database operations
- **Pydantic** - Data validation
- **Scikit-learn** - Machine learning
- **Passlib + Bcrypt** - Password hashing
- **Python-Jose** - JWT token handling

### Frontend
- **React 18** - UI library
- **TypeScript** - Type safety
- **TailwindCSS** - Utility-first CSS
- **Recharts** - Data visualization
- **React Router v6** - Navigation
- **Lucide React** - Icons

### Infrastructure
- **Docker + Docker Compose** - Containerization
- **PostgreSQL 15** - Production database
- **Redis 7** - Caching (optional)

---

## Installation

### Prerequisites

- Python 3.9 or higher
- Node.js 18 or higher
- npm or yarn

### Backend Setup

```bash
# Navigate to backend directory
cd zero-trust-firewall/backend

# Create virtual environment
python -m venv venv

# Activate virtual environment
# On macOS/Linux:
source venv/bin/activate
# On Windows:
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Frontend Setup

```bash
# Navigate to frontend directory
cd zero-trust-firewall/frontend

# Install dependencies
npm install
```

### Environment Configuration

Create a `.env` file in the backend directory (copy from `.env.example`):

```env
# Database
DATABASE_URL=sqlite:///./zerotrust.db

# Security
SECRET_KEY=your-super-secret-key-change-in-production
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=30

# Server
HOST=0.0.0.0
PORT=8000
DEBUG=true

# CORS
CORS_ORIGINS=["http://localhost:3000"]
```

---

## Running the Application

### Development Mode

**Terminal 1 - Backend:**
```bash
cd zero-trust-firewall/backend
source venv/bin/activate
python -m uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

**Terminal 2 - Frontend:**
```bash
cd zero-trust-firewall/frontend
npm run dev
```

### Access Points

| Service | URL |
|---------|-----|
| Frontend | http://localhost:3000 |
| Backend API | http://localhost:8000 |
| API Docs (Swagger) | http://localhost:8000/docs |
| API Docs (ReDoc) | http://localhost:8000/redoc |
| Health Check | http://localhost:8000/health |

### Default Credentials

| Username | Password | Role |
|----------|----------|------|
| admin | admin123 | Administrator |

> **Important:** Change the default password immediately in production!

### Docker Mode (Production)

```bash
# Build and start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
```

---

## User Guide

### Getting Started

1. **Login**: Navigate to http://localhost:3000 and enter credentials
2. **Dashboard**: View real-time security metrics
3. **Scan URLs**: Use the URL Scanner to check suspicious links
4. **Monitor Threats**: Review the Threat Log for scan history
5. **Manage Alerts**: Check and acknowledge security alerts

### URL Scanning

#### Single URL Scan

1. Navigate to **URL Scanner** in the sidebar
2. Enter the URL in the input field (e.g., `https://suspicious-site.com/login`)
3. Click **Scan URL**
4. View results including:
   - Phishing detection result (Safe/Phishing)
   - Confidence score (0-100%)
   - ML model score
   - Rule-based score
   - Matched detection rules
   - Extracted features

#### Batch URL Scan

1. Click **Batch Scan** tab
2. Enter multiple URLs (one per line, max 100)
3. Click **Scan All**
4. View aggregated results

### Understanding Scan Results

| Field | Description |
|-------|-------------|
| **Status** | Safe (green) or Phishing (red) |
| **Confidence** | Overall detection confidence (0-100%) |
| **ML Score** | Machine learning model confidence |
| **Rule Score** | Rule-based detection score |
| **Severity** | Critical, High, Medium, Low, Info |
| **Matched Rules** | Which detection rules triggered |

### Severity Levels

| Severity | Confidence Range | Action |
|----------|-----------------|--------|
| Critical | 90-100% | Immediate block |
| High | 70-90% | Block and alert |
| Medium | 50-70% | Warning |
| Low | 30-50% | Monitor |
| Info | 0-30% | Informational |

### Detection Rules

The system uses 12 detection rules:

1. **Suspicious TLD** - Detects risky top-level domains (.xyz, .tk, .ml, etc.)
2. **IP Address URL** - URLs using IP address instead of domain name
3. **Long URL** - Unusually long URLs (>100 characters)
4. **Many Subdomains** - Excessive subdomain depth (>3 levels)
5. **Suspicious Keywords** - Login, verify, update, secure, account patterns
6. **URL Shortener** - bit.ly, tinyurl, goo.gl detection
7. **Homograph Attack** - Unicode character substitution (e.g., 'а' vs 'a')
8. **Typosquatting** - Common brand misspellings (gooogle, faceb00k)
9. **Data URI** - Embedded data:// URLs
10. **Excessive Hyphens** - Many hyphens in domain name
11. **Numeric Domain** - High digit ratio in domain
12. **High Entropy** - Randomized URL strings

### Network Monitoring

The Network Monitor shows:

- **Active Connections**: Current network sessions
- **Bandwidth Usage**: Upload/download over time
- **Protocol Distribution**: HTTP, HTTPS, DNS breakdown
- **Geographic Data**: Connection origin countries
- **Threat Score**: Per-connection risk assessment

### Alert Management

Alerts are generated for:

- Phishing URL detections
- Blocked connections
- Policy violations
- System anomalies

**Alert Severities:**
- **Critical** - Immediate action required
- **High** - Important security event
- **Medium** - Notable activity
- **Low** - Informational

**Alert Actions:**
- Mark as Read
- Acknowledge (with timestamp)
- View Details

---

## API Documentation

### Authentication Endpoints

#### Login
```http
POST /api/auth/login
Content-Type: application/x-www-form-urlencoded

username=admin&password=admin123
```

Response:
```json
{
  "access_token": "eyJhbGc...",
  "refresh_token": "eyJhbGc...",
  "token_type": "bearer"
}
```

#### Get Current User
```http
GET /api/auth/me
Authorization: Bearer <access_token>
```

Response:
```json
{
  "id": 1,
  "email": "admin@example.com",
  "username": "admin",
  "full_name": "System Administrator",
  "role": "admin",
  "is_active": true,
  "is_verified": true,
  "created_at": "2024-01-15T10:00:00Z"
}
```

#### Refresh Token
```http
POST /api/auth/refresh
Content-Type: application/json

{
  "refresh_token": "eyJhbGc..."
}
```

#### Register New User
```http
POST /api/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "username": "newuser",
  "password": "securepassword123",
  "full_name": "New User"
}
```

### URL Scanning Endpoints

#### Scan Single URL
```http
POST /api/urls/scan
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "url": "https://suspicious-site.com/login"
}
```

Response:
```json
{
  "id": 1,
  "url": "https://suspicious-site.com/login",
  "domain": "suspicious-site.com",
  "is_phishing": true,
  "confidence_score": 0.87,
  "ml_score": 0.82,
  "rule_score": 0.92,
  "severity": "high",
  "status": "blocked",
  "features": {
    "url_length": 45,
    "domain_length": 20,
    "entropy": 3.8,
    "has_https": true,
    "suspicious_keywords": ["login"],
    "num_subdomains": 1
  },
  "matched_rules": ["suspicious_keywords", "high_entropy"],
  "scanned_at": "2024-01-15T10:30:00Z"
}
```

#### Batch Scan
```http
POST /api/urls/batch-scan
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "urls": [
    "https://site1.com",
    "https://site2.com",
    "https://site3.com"
  ]
}
```

#### Get Scan History
```http
GET /api/urls/scans?page=1&page_size=20&is_phishing=true&severity=high
Authorization: Bearer <access_token>
```

Query Parameters:
- `page` - Page number (default: 1)
- `page_size` - Items per page (default: 20, max: 100)
- `is_phishing` - Filter by phishing status (true/false)
- `severity` - Filter by severity (critical/high/medium/low/info)
- `domain` - Filter by domain

### Dashboard Endpoints

#### Get Statistics
```http
GET /api/dashboard/stats?days=7
Authorization: Bearer <access_token>
```

Response:
```json
{
  "total_scans": 1523,
  "phishing_detected": 234,
  "blocked_threats": 198,
  "active_alerts": 12,
  "scan_rate": 45.2,
  "detection_rate": 15.4
}
```

#### Get Severity Distribution
```http
GET /api/dashboard/severity-distribution?days=7
Authorization: Bearer <access_token>
```

#### Get Threat Trends
```http
GET /api/dashboard/trends?days=7
Authorization: Bearer <access_token>
```

#### Get Recent Threats
```http
GET /api/dashboard/recent-threats?limit=5
Authorization: Bearer <access_token>
```

#### Get Top Blocked Domains
```http
GET /api/dashboard/top-blocked-domains?limit=5&days=7
Authorization: Bearer <access_token>
```

### Alert Endpoints

#### List Alerts
```http
GET /api/alerts?page=1&page_size=20&severity=high&is_read=false
Authorization: Bearer <access_token>
```

#### Get Unread Alerts
```http
GET /api/alerts/unread?limit=5
Authorization: Bearer <access_token>
```

#### Update Alert
```http
PUT /api/alerts/{alert_id}
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "is_read": true,
  "is_acknowledged": true
}
```

#### Create Alert
```http
POST /api/alerts
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "title": "Suspicious Activity Detected",
  "description": "Multiple failed login attempts from IP 192.168.1.100",
  "severity": "high",
  "alert_type": "security",
  "source": "auth_monitor"
}
```

### Network Endpoints

#### Get Connections
```http
GET /api/network/connections?page=1&page_size=20
Authorization: Bearer <access_token>
```

#### Get Bandwidth Stats
```http
GET /api/network/bandwidth?hours=24
Authorization: Bearer <access_token>
```

#### Get Protocol Distribution
```http
GET /api/network/protocols?hours=24
Authorization: Bearer <access_token>
```

#### Get Real-Time Stats
```http
GET /api/network/real-time
Authorization: Bearer <access_token>
```

### Threat Intelligence Endpoints

#### Get Threat Indicators
```http
GET /api/threats/intel?page=1&page_size=20&indicator_type=domain
Authorization: Bearer <access_token>
```

#### Add Threat Indicator
```http
POST /api/threats/intel
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "indicator": "malicious-domain.com",
  "indicator_type": "domain",
  "threat_type": "phishing",
  "severity": "high",
  "description": "Known phishing domain"
}
```

---

## Security Features

### Zero Trust Implementation

1. **Identity Verification**
   - JWT-based authentication
   - Token expiration (30 min access, 7 days refresh)
   - Secure password hashing (bcrypt)

2. **Least Privilege Access**
   - Role-based access control (RBAC)
   - API endpoint authorization
   - Resource-level permissions

3. **Continuous Validation**
   - Token verification on each request
   - Session monitoring
   - Audit logging

### ML Detection Model

The phishing detection model uses a Random Forest classifier trained on URL features:

**Feature Categories:**

| Category | Features |
|----------|----------|
| Length | URL length, domain length, path length |
| Characters | Dots, hyphens, underscores, digits, special chars |
| Structure | Has IP, has HTTPS, has port, subdomain count |
| Entropy | Shannon entropy of URL |
| Keywords | Suspicious terms (login, verify, secure, etc.) |
| TLD | Suspicious top-level domain check |

### Rule-Based Detection

Complements ML with deterministic rules for:
- Known phishing patterns
- Brand impersonation (typosquatting)
- Unicode attacks (homographs)
- URL obfuscation techniques

### Password Security

- Passwords are hashed using bcrypt with salt
- Minimum 8 characters required
- Password change requires current password verification

---

## Configuration

### Backend Configuration

Edit `backend/app/core/config.py` or use environment variables:

```python
# Database
DATABASE_URL = "sqlite:///./zerotrust.db"  # or postgresql://...

# Security
SECRET_KEY = "your-secret-key"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

# ML Model
ML_MODEL_PATH = "app/ml/model.pkl"
ML_THRESHOLD = 0.5  # Phishing threshold

# Rate Limiting
RATE_LIMIT_PER_MINUTE = 60

# CORS
CORS_ORIGINS = ["http://localhost:3000"]
```

### Frontend Configuration

Edit `frontend/vite.config.ts` for proxy settings:

```typescript
server: {
  port: 3000,
  proxy: {
    '/api': {
      target: 'http://127.0.0.1:8000',
      changeOrigin: true,
    },
  },
}
```

### Docker Configuration

Edit `docker-compose.yml` for production settings:

```yaml
services:
  backend:
    environment:
      - DATABASE_URL=postgresql://postgres:postgres@db:5432/zerotrust_db
      - SECRET_KEY=your-production-secret-key
      - DEBUG=false
```

---

## Troubleshooting

### Common Issues

#### Backend won't start

1. Check Python version: `python --version` (needs 3.9+)
2. Verify virtual environment is activated
3. Install dependencies: `pip install -r requirements.txt`
4. Check port 8000 is available: `lsof -i :8000`

#### Frontend connection errors

1. Ensure backend is running on port 8000
2. Check Vite proxy configuration uses `127.0.0.1` not `localhost`
3. Clear browser cache and cookies
4. Check CORS settings in backend config

#### Database errors

1. Delete `zerotrust.db` to reset database
2. Restart backend to recreate tables
3. For PostgreSQL, verify connection string and credentials

#### Authentication failures

1. Verify credentials (default: admin/admin123)
2. Check token expiration (30 min default)
3. Clear localStorage and login again
4. Check backend logs for JWT errors

#### "No such function: date_trunc" error

This occurs when using PostgreSQL-specific SQL with SQLite. The codebase has been updated to use SQLite-compatible functions. If you see this error, pull the latest code.

### Logs

**Backend logs:**
```bash
# View real-time logs (if using uvicorn)
# Logs appear in the terminal running the server

# Or check Docker logs
docker-compose logs -f backend
```

**Frontend logs:**
- Open browser DevTools (F12)
- Check Console and Network tabs

### Performance Tips

1. **Database**: Use PostgreSQL for production workloads
2. **Caching**: Enable Redis for API caching
3. **ML Model**: Pre-load model on startup (already implemented)
4. **Frontend**: Enable gzip compression in production

---

## Project Structure

```
zero-trust-firewall/
├── backend/
│   ├── app/
│   │   ├── api/                    # API route handlers
│   │   │   ├── __init__.py         # Router aggregation
│   │   │   ├── auth.py             # Authentication endpoints
│   │   │   ├── urls.py             # URL scanning endpoints
│   │   │   ├── dashboard.py        # Dashboard statistics
│   │   │   ├── alerts.py           # Alert management
│   │   │   ├── network.py          # Network monitoring
│   │   │   └── threats.py          # Threat intelligence
│   │   ├── core/
│   │   │   ├── config.py           # Configuration settings
│   │   │   ├── security.py         # Auth utilities (JWT, hashing)
│   │   │   └── database.py         # Database connection
│   │   ├── models/
│   │   │   ├── __init__.py         # Model exports
│   │   │   ├── user.py             # User model
│   │   │   └── threat.py           # Threat-related models
│   │   ├── schemas/
│   │   │   ├── user.py             # User Pydantic schemas
│   │   │   └── threat.py           # Threat Pydantic schemas
│   │   ├── services/
│   │   │   ├── phishing_detector.py  # Main detection service
│   │   │   ├── ml_detector.py        # ML model wrapper
│   │   │   ├── rule_engine.py        # Rule-based detection
│   │   │   ├── url_analyzer.py       # Feature extraction
│   │   │   ├── threat_intel.py       # Threat intelligence
│   │   │   └── network_monitor.py    # Network analysis
│   │   └── ml/
│   │       ├── model.pkl           # Trained ML model
│   │       └── train_model.py      # Model training script
│   ├── main.py                     # FastAPI application entry
│   ├── requirements.txt            # Python dependencies
│   └── zerotrust.db               # SQLite database (auto-created)
├── frontend/
│   ├── src/
│   │   ├── components/            # Reusable React components
│   │   │   ├── Dashboard/         # Dashboard widgets
│   │   │   ├── URLScanner/        # URL scanning interface
│   │   │   ├── ThreatLog/         # Threat history table
│   │   │   ├── NetworkMonitor/    # Network visualization
│   │   │   ├── Alerts/            # Alert management
│   │   │   └── Layout/            # Layout components
│   │   ├── pages/                 # Page components
│   │   │   ├── LoginPage.tsx      # Login form
│   │   │   ├── RegisterPage.tsx   # Registration form
│   │   │   └── DashboardPage.tsx  # Main dashboard
│   │   ├── context/
│   │   │   └── AuthContext.tsx    # Authentication state
│   │   ├── services/
│   │   │   └── api.ts             # API client
│   │   ├── hooks/                 # Custom React hooks
│   │   ├── utils/                 # Utility functions
│   │   ├── App.tsx               # Root component
│   │   └── main.tsx              # Entry point
│   ├── public/                    # Static assets
│   ├── index.html                # HTML template
│   ├── package.json              # Node.js dependencies
│   ├── tailwind.config.js        # TailwindCSS config
│   ├── tsconfig.json             # TypeScript config
│   └── vite.config.ts            # Vite bundler config
├── docker-compose.yml            # Production Docker config
├── docker-compose.dev.yml        # Development Docker config
├── Dockerfile.backend            # Backend container
├── Dockerfile.frontend           # Frontend container
├── .env.example                  # Environment template
├── .gitignore                    # Git ignore rules
└── README.md                     # This file
```

---

## License

MIT License - See LICENSE file for details.

---

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Create a Pull Request

---

## Support

For issues and feature requests, please create an issue in the repository.

---

**Built with security in mind. Stay safe online.**
