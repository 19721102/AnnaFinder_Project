from fastapi import APIRouter

from backend.api.v1.routes import auth as auth_routes, meta as meta_routes

api_v1_router = APIRouter()

api_v1_router.include_router(meta_routes.router, tags=["v1"])
api_v1_router.include_router(auth_routes.router, prefix="/auth", tags=["auth"])
