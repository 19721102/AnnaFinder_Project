from fastapi import APIRouter

from backend.api.v1.routes import (
    auth as auth_routes,
    audit as audit_routes,
    events as events_routes,
    families as families_routes,
    families_bootstrap as families_bootstrap_routes,
    item_tags as item_tag_routes,
    items as items_routes,
    locations as locations_routes,
    meta as meta_routes,
    observability as observability_routes,
    tags as tags_routes,
)

api_v1_router = APIRouter()

api_v1_router.include_router(meta_routes.router, tags=["meta"])
api_v1_router.include_router(auth_routes.router, prefix="/auth", tags=["auth"])
api_v1_router.include_router(families_routes.router, tags=["families"])
api_v1_router.include_router(families_bootstrap_routes.router, tags=["families"])
api_v1_router.include_router(locations_routes.router, tags=["locations"])
api_v1_router.include_router(items_routes.router, tags=["items"])
api_v1_router.include_router(tags_routes.router, tags=["tags"])
api_v1_router.include_router(item_tag_routes.router, tags=["item-tags"])
api_v1_router.include_router(events_routes.router, tags=["events"])
api_v1_router.include_router(audit_routes.router, tags=["audit"])
api_v1_router.include_router(observability_routes.router, tags=["observability"])
