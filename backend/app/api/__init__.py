from fastapi import APIRouter

from app.api.routes.admin import router as admin_router
from app.api.routes.auth import router as auth_router
from app.api.routes.checks import router as checks_router
from app.api.routes.health import router as health_router
from app.api.routes.proxies import router as proxies_router
from app.api.routes.watchlist import router as watchlist_router


api_router = APIRouter()
api_router.include_router(auth_router)
api_router.include_router(admin_router)
api_router.include_router(health_router)
api_router.include_router(checks_router)
api_router.include_router(proxies_router)
api_router.include_router(watchlist_router)
