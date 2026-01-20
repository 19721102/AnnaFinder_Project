from fastapi import APIRouter

from backend.api.v1.routes import meta as meta_routes

api_v1_router = APIRouter()

api_v1_router.include_router(meta_routes.router, tags=["v1"])
