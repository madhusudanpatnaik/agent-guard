"""Multi-tenancy helpers — scope every query and object access to one org.

The rule is simple and applied everywhere: a principal (console user or agent)
only ever sees or touches rows whose ``org_id`` equals its own. Cross-org access
returns 404 (never reveal existence across tenants).
"""

from __future__ import annotations

from typing import Any, TypeVar

from fastapi import HTTPException, status

from .models import User

T = TypeVar("T")


def scope(query, model, user: User):
    """Add an ``org_id`` filter for the user's tenant to a SELECT."""
    return query.where(model.org_id == user.org_id)


def owned_or_404(obj: T | None, user: User, what: str = "Resource") -> T:
    """Return ``obj`` only if it belongs to the user's org; else 404."""
    if obj is None or getattr(obj, "org_id", None) != user.org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"{what} not found")
    return obj


def same_org(obj: Any, user: User) -> bool:
    return obj is not None and getattr(obj, "org_id", None) == user.org_id
