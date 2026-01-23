from __future__ import annotations

from fastapi import APIRouter, Depends

from backend.api.v1.deps.auth import require_family_access

router = APIRouter()


@router.get("/families/{family_id}/me")
def get_family_membership(
    membership=Depends(require_family_access),
) -> dict[str, str]:
    return {
        "family_id": membership["family_id"],
        "user_id": membership["user_id"],
        "role": membership["role"],
    }
