from fastapi import APIRouter
from .auth import router as auth_router
from .urls import router as urls_router
from .threats import router as threats_router
from .network import router as network_router
from .dashboard import router as dashboard_router
from .alerts import router as alerts_router
from .users import router as users_router

api_router = APIRouter(prefix="/api")

api_router.include_router(auth_router)
api_router.include_router(urls_router)
api_router.include_router(threats_router)
api_router.include_router(network_router)
api_router.include_router(dashboard_router)
api_router.include_router(alerts_router)
api_router.include_router(users_router)
