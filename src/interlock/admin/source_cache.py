"""Clear a source's cached answers when the console changes or removes it."""

from __future__ import annotations

import logging

from starlette.requests import Request

logger = logging.getLogger(__name__)


async def invalidate_source_cache(request: Request, source_id: str) -> None:
    """Drop every cached answer for `source_id`, on every gateway.

    Called after a source is edited, disabled or deleted. The gateways also
    clear a source when their registry reload stops loading it; this covers
    edits, which keep the source loaded, and gateways whose reload lags.
    A failure is logged, never raised: the change itself has been saved.
    """
    invalidator = getattr(request.app.state, "cache_invalidator", None)
    if invalidator is None:
        return
    try:
        await invalidator.invalidate_for_source(source_id)
    except Exception:
        logger.warning("Cache invalidation failed for source=%s", source_id, exc_info=True)


async def notify_source_change(request: Request, channel: str = "onyx_config_changed") -> None:
    """Publish after commit; failed notification must not skip cache invalidation."""
    try:
        async with request.app.state.pg_pool.acquire() as conn:
            await conn.execute(f"NOTIFY {channel}")
    except Exception:
        logger.warning("Source configuration notification failed", exc_info=True)
