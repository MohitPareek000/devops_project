from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
import uvicorn

from app.core.config import settings
from app.core.database import init_db, engine, Base
from app.api import api_router
from app.services.threat_intel import threat_intel
from app.models import User
from app.core.security import get_password_hash


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events."""
    # Startup
    print("Starting Zero Trust Firewall...")

    # Initialize database
    Base.metadata.create_all(bind=engine)
    print("Database initialized")

    # Create default admin user if not exists
    from app.core.database import SessionLocal
    db = SessionLocal()
    try:
        admin = db.query(User).filter(User.username == "admin").first()
        if not admin:
            admin = User(
                email="admin@zerotrust.example.com",
                username="admin",
                full_name="System Administrator",
                hashed_password=get_password_hash("admin123"),
                role="admin",
                is_active=True,
                is_verified=True
            )
            db.add(admin)
            db.commit()
            print("Default admin user created (username: admin, password: admin123)")
    finally:
        db.close()

    # Initialize threat intelligence
    print("Loading threat intelligence...")
    await threat_intel.update_blacklist()

    print("Zero Trust Firewall is ready!")

    yield

    # Shutdown
    print("Shutting down Zero Trust Firewall...")


# Create FastAPI application
app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Zero Trust Firewall with ML-Powered Phishing URL Detection",
    lifespan=lifespan
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Global exception handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={
            "detail": "Internal server error",
            "message": str(exc) if settings.DEBUG else "An unexpected error occurred"
        }
    )


# Include API routes
app.include_router(api_router)


# Health check endpoint
@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "app": settings.APP_NAME,
        "version": settings.APP_VERSION
    }


# Root endpoint
@app.get("/")
async def root():
    return {
        "message": "Zero Trust Firewall API",
        "version": settings.APP_VERSION,
        "docs": "/docs"
    }


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host=settings.HOST,
        port=settings.PORT,
        reload=settings.DEBUG
    )
