import os

from fastapi import APIRouter

router = APIRouter()


@router.get("/meta")
async def meta():
    return {"service": "AnnaFinder", "api": "v1", "status": "ok"}


_env = os.getenv("APP_ENV") or os.getenv("ANNAFINDER_ENV", "dev")
_env = _env.strip().lower()
_enable_test_routes = _env != "prod"


if _enable_test_routes:
    @router.get("/_test/validation")
    async def validation_test(value: int):
        return {"received": value}
