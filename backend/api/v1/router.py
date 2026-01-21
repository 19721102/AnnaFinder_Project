from fastapi import APIRouter

from backend.api.v1.routes import (
    auth as auth_routes,
    families as families_routes,
    items as items_routes,
    locations as locations_routes,
    meta as meta_routes,
)

api_v1_router = APIRouter()

api_v1_router.include_router(meta_routes.router, tags=["v1"])
api_v1_router.include_router(auth_routes.router, prefix="/auth", tags=["auth"])
api_v1_router.include_router(families_routes.router, tags=["families"])
api_v1_router.include_router(locations_routes.router, tags=["locations"])
api_v1_router.include_router(items_routes.router, tags=["items"])
