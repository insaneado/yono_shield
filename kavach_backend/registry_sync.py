# =============================================================================
# KAVACH — registry_sync.py (Dynamic Domain Whitelist Synchronization Engine)
# =============================================================================
#
# Eliminates the hardcoded WHITELISTED_DOMAINS set in scanner.py by pulling
# authorized marketing and banking domains from a Central Registry API.
#
# Architecture:
#   ┌──────────────────────────────────────────────────────────────────────┐
#   │  FastAPI Lifespan (main.py)                                         │
#   │    └─ startup: run_initial_sync() ──► immediate first pull          │
#   │    └─ startup: start_scheduler()  ──► APScheduler background job    │
#   │                                                                      │
#   │  APScheduler (BackgroundScheduler)                                   │
#   │    └─ Every 6 hours: _sync_from_registry()                          │
#   │         │                                                            │
#   │         ▼                                                            │
#   │    HTTP GET → SBI Central Registry API (mock endpoint)              │
#   │         │                                                            │
#   │         ▼                                                            │
#   │    Parse JSON → validate domains → update global thread-safe set    │
#   │                                                                      │
#   │  scanner.py                                                          │
#   │    └─ get_whitelisted_domains() ──► reads live in-memory set         │
#   └──────────────────────────────────────────────────────────────────────┘
#
# Sync Resilience:
#   - If the registry API is unreachable, the engine falls back to a
#     hardcoded seed set of core banking domains (never empty).
#   - If a sync fetches an empty or malformed response, the existing
#     whitelist is preserved (never wiped).
#   - All sync operations are logged with domain count diffs.
#
# Thread Safety:
#   - The global whitelist is stored as a frozenset and swapped atomically.
#   - Readers (scanner.py) never need locks — frozenset is immutable.
#   - The writer (sync job) builds a new frozenset, then replaces the ref.
# =============================================================================

from __future__ import annotations

import logging
import os
import threading
from datetime import datetime, timezone

import requests

logger = logging.getLogger("kavach.registry_sync")

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────

# Central Registry API endpoint.
# In production, this would be an internal SBI microservice.
# For the MVP, we use a GitHub-hosted JSON file that we control.
REGISTRY_URL: str = os.environ.get(
    "SBI_REGISTRY_URL",
    "https://raw.githubusercontent.com/insaneado/yono_shield/main/registry/whitelist.json",
)

# Sync interval in hours.
SYNC_INTERVAL_HOURS: int = 6

# HTTP timeout for the registry fetch (connect, read) in seconds.
_REGISTRY_FETCH_TIMEOUT: tuple[float, float] = (5.0, 10.0)

# ─────────────────────────────────────────────────────────────────────────────
# SEED DOMAINS — Hardcoded fallback (NEVER empty)
# ─────────────────────────────────────────────────────────────────────────────
# These core banking portals are baked in as a safety net.  Even if the
# registry API is permanently unreachable, the scanner will NEVER flag
# official SBI domains as phishing.  The registry sync EXTENDS this set
# with new marketing / campaign domains — it never replaces it.

_SEED_DOMAINS: frozenset[str] = frozenset({
    # ── Core banking portals ──
    "onlinesbi.sbi",
    "sbiyono.sbi",
    "sbi.co.in",
    "bank.sbi",
    "www.onlinesbi.sbi",
    "www.sbiyono.sbi",
    "www.sbi.co.in",
    "www.bank.sbi",
})

# ─────────────────────────────────────────────────────────────────────────────
# GLOBAL THREAD-SAFE WHITELIST
# ─────────────────────────────────────────────────────────────────────────────
# Using a frozenset for atomic reference swap — readers never need locks.
# The _lock is only used by the writer to prevent concurrent syncs.

_whitelist_lock = threading.Lock()
_active_whitelist: frozenset[str] = _SEED_DOMAINS
_last_sync_time: str | None = None
_last_sync_source: str = "SEED"


def get_whitelisted_domains() -> frozenset[str]:
    """Return the current live whitelist.

    Called by scanner.py on every URL scan.  Returns a frozenset that is
    safe to iterate without locks (immutable snapshot).
    """
    return _active_whitelist


def get_sync_status() -> dict:
    """Return the current sync status for the /health endpoint."""
    return {
        "whitelist_size": len(_active_whitelist),
        "last_sync_time": _last_sync_time,
        "last_sync_source": _last_sync_source,
        "registry_url": REGISTRY_URL,
        "sync_interval_hours": SYNC_INTERVAL_HOURS,
    }


# ─────────────────────────────────────────────────────────────────────────────
# SYNC ENGINE
# ─────────────────────────────────────────────────────────────────────────────

def _sync_from_registry() -> None:
    """Fetch the domain whitelist from the Central Registry API.

    Expected JSON format:
    {
        "version": "2026-04-30",
        "domains": [
            "onlinesbi.sbi",
            "sbiyono.sbi",
            "sbi-yono-offers.in",
            ...
        ]
    }

    Resilience rules:
      - If the fetch fails → keep existing whitelist, log warning.
      - If the response is empty or has no 'domains' key → keep existing.
      - If domains list is non-empty → merge with seed set, swap atomically.
    """
    global _active_whitelist, _last_sync_time, _last_sync_source

    with _whitelist_lock:
        old_count = len(_active_whitelist)
        logger.info(
            "Registry sync starting — current whitelist has %d domains",
            old_count,
        )

        try:
            response = requests.get(
                REGISTRY_URL,
                timeout=_REGISTRY_FETCH_TIMEOUT,
                headers={
                    "Accept": "application/json",
                    "User-Agent": "KAVACH-RegistrySync/1.0",
                },
            )
            response.raise_for_status()

            data = response.json()

            # ── Validate response structure ──
            if not isinstance(data, dict):
                logger.warning(
                    "Registry response is not a JSON object — keeping existing whitelist"
                )
                return

            raw_domains = data.get("domains", [])
            if not isinstance(raw_domains, list) or len(raw_domains) == 0:
                logger.warning(
                    "Registry returned empty or missing 'domains' list — "
                    "keeping existing whitelist (%d domains)",
                    old_count,
                )
                return

            # ── Normalize and validate each domain ──
            validated: set[str] = set()
            for domain in raw_domains:
                if not isinstance(domain, str):
                    continue
                normalized = domain.strip().lower()
                # Basic domain validation: must contain a dot, no spaces
                if "." in normalized and " " not in normalized and len(normalized) > 3:
                    validated.add(normalized)

            if not validated:
                logger.warning(
                    "Registry returned domains but none passed validation — "
                    "keeping existing whitelist (%d domains)",
                    old_count,
                )
                return

            # ── Merge with seed domains (seed is NEVER removed) ──
            merged = _SEED_DOMAINS | frozenset(validated)

            # ── Atomic swap ──
            _active_whitelist = merged
            _last_sync_time = datetime.now(timezone.utc).isoformat()
            _last_sync_source = "REGISTRY"

            new_domains = merged - frozenset({*_SEED_DOMAINS})
            logger.info(
                "✅ Registry sync complete — %d total domains "
                "(%d from seed, %d from registry, version=%s)",
                len(merged),
                len(_SEED_DOMAINS),
                len(new_domains),
                data.get("version", "unknown"),
            )

        except requests.exceptions.Timeout:
            logger.warning(
                "Registry sync TIMEOUT (%s) — keeping existing whitelist (%d domains)",
                REGISTRY_URL,
                old_count,
            )
        except requests.exceptions.ConnectionError:
            logger.warning(
                "Registry sync CONNECTION ERROR (%s) — keeping existing whitelist (%d domains)",
                REGISTRY_URL,
                old_count,
            )
        except requests.exceptions.RequestException as exc:
            logger.warning(
                "Registry sync FAILED (%s: %s) — keeping existing whitelist (%d domains)",
                type(exc).__name__,
                exc,
                old_count,
            )
        except (ValueError, KeyError, TypeError) as exc:
            logger.warning(
                "Registry sync PARSE ERROR (%s: %s) — keeping existing whitelist (%d domains)",
                type(exc).__name__,
                exc,
                old_count,
            )
        except Exception as exc:
            logger.error(
                "Registry sync UNEXPECTED ERROR (%s: %s) — keeping existing whitelist (%d domains)",
                type(exc).__name__,
                exc,
                old_count,
            )


# ─────────────────────────────────────────────────────────────────────────────
# SCHEDULER — APScheduler BackgroundScheduler
# ─────────────────────────────────────────────────────────────────────────────

_scheduler = None


def run_initial_sync() -> None:
    """Execute the first sync immediately on server startup.

    Called from main.py's lifespan context manager before the app starts
    accepting requests.  This ensures the whitelist is populated from the
    registry before the first scan arrives.
    """
    logger.info("Running initial registry sync on startup...")
    _sync_from_registry()


def start_scheduler() -> None:
    """Start the APScheduler background job for periodic registry sync.

    Fires _sync_from_registry() every SYNC_INTERVAL_HOURS hours.
    Uses APScheduler's BackgroundScheduler which runs in a daemon thread
    and does not block the FastAPI event loop.
    """
    global _scheduler

    try:
        from apscheduler.schedulers.background import BackgroundScheduler
    except ImportError:
        logger.error(
            "apscheduler is not installed — periodic registry sync DISABLED. "
            "Install with: pip install apscheduler"
        )
        return

    _scheduler = BackgroundScheduler(daemon=True)
    _scheduler.add_job(
        _sync_from_registry,
        trigger="interval",
        hours=SYNC_INTERVAL_HOURS,
        id="registry_sync",
        name="SBI Domain Registry Sync",
        replace_existing=True,
    )
    _scheduler.start()

    logger.info(
        "📡 Registry sync scheduler started — syncing every %d hours",
        SYNC_INTERVAL_HOURS,
    )


def stop_scheduler() -> None:
    """Gracefully shut down the APScheduler on app shutdown."""
    global _scheduler

    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None
        logger.info("Registry sync scheduler stopped")
