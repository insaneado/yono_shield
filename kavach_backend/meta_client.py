# =============================================================================
# KAVACH — meta_client.py (Meta Graph API WhatsApp Client)
# =============================================================================
#
# Modular client for the Meta WhatsApp Cloud API (Graph API v18.0).
# Handles:
#   - Sending text replies to users via WhatsApp
#   - Downloading media (images) from WhatsApp CDN
#   - Loading credentials from .env via python-dotenv
#
# All outbound requests are wrapped in error handling so a token expiry
# or network issue never crashes the FastAPI server.
# =============================================================================

from __future__ import annotations

import logging
import os

import requests
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("kavach.meta_client")

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION — loaded from .env (never hardcoded)
# ─────────────────────────────────────────────────────────────────────────────

META_ACCESS_TOKEN: str = os.getenv("META_ACCESS_TOKEN", "")
META_PHONE_NUMBER_ID: str = os.getenv("META_PHONE_NUMBER_ID", "")
META_VERIFY_TOKEN: str = os.getenv("META_VERIFY_TOKEN", "kavach_verify_token_2026")

# Graph API base URL — version pinned for stability.
_GRAPH_API_BASE = "https://graph.facebook.com/v18.0"


# ─────────────────────────────────────────────────────────────────────────────
# OUTBOUND: Send WhatsApp Text Reply
# ─────────────────────────────────────────────────────────────────────────────


def send_whatsapp_reply(to_phone_number: str, message_text: str) -> bool:
    """Send a text message reply to a WhatsApp user via the Meta Graph API.

    Uses the official Messages endpoint:
      POST https://graph.facebook.com/v18.0/{PHONE_NUMBER_ID}/messages

    The META_ACCESS_TOKEN is passed as a Bearer token in the Authorization
    header.  If credentials are missing or the API call fails, the error
    is logged to the console but the server keeps running.

    Args:
        to_phone_number: The recipient's WhatsApp number in international
                         format without '+' (e.g. "919876543210").
        message_text:    The reply body to send.

    Returns:
        True if the message was sent successfully, False otherwise.
    """
    # ── Always log the reply to console (useful for demo / debugging) ──
    logger.info("━" * 60)
    logger.info("📤 OUTBOUND REPLY → %s", to_phone_number)
    logger.info("   %s", message_text)
    logger.info("━" * 60)

    # ── Guard: credentials must be configured ──
    if not META_ACCESS_TOKEN:
        logger.warning(
            "META_ACCESS_TOKEN not set — reply logged but NOT sent to WhatsApp. "
            "Set it in your .env file to enable live delivery."
        )
        return False

    if not META_PHONE_NUMBER_ID:
        logger.warning(
            "META_PHONE_NUMBER_ID not set — reply logged but NOT sent to WhatsApp. "
            "Set it in your .env file to enable live delivery."
        )
        return False

    # ── Build the Meta Graph API request ──
    url = f"{_GRAPH_API_BASE}/{META_PHONE_NUMBER_ID}/messages"

    headers = {
        "Authorization": f"Bearer {META_ACCESS_TOKEN}",
        "Content-Type": "application/json",
    }

    payload = {
        "messaging_product": "whatsapp",
        "to": to_phone_number,
        "type": "text",
        "text": {"body": message_text},
    }

    # ── Fire the request ──
    try:
        resp = requests.post(url, json=payload, headers=headers, timeout=10)
        resp.raise_for_status()

        resp_data = resp.json()
        message_id = (
            resp_data.get("messages", [{}])[0].get("id", "unknown")
            if resp_data.get("messages")
            else "unknown"
        )

        logger.info(
            "✅ WhatsApp reply sent successfully (message_id=%s)", message_id
        )
        return True

    except requests.exceptions.HTTPError as exc:
        # Token expired, permission denied, invalid phone number, etc.
        status_code = exc.response.status_code if exc.response else "?"
        error_body = ""
        try:
            error_body = exc.response.json() if exc.response else {}
        except Exception:
            error_body = exc.response.text if exc.response else ""

        logger.error(
            "❌ Meta API HTTP %s error sending reply to %s: %s",
            status_code,
            to_phone_number,
            error_body,
        )
        return False

    except requests.exceptions.ConnectionError:
        logger.error(
            "❌ Connection error — cannot reach Meta Graph API at %s", url
        )
        return False

    except requests.exceptions.Timeout:
        logger.error(
            "❌ Timeout — Meta Graph API did not respond within 10s"
        )
        return False

    except requests.RequestException as exc:
        logger.error(
            "❌ Unexpected error sending WhatsApp reply: %s", exc
        )
        return False


# ─────────────────────────────────────────────────────────────────────────────
# INBOUND: Download Media from WhatsApp CDN
# ─────────────────────────────────────────────────────────────────────────────


def download_whatsapp_media(media_id: str) -> bytes | None:
    """Download media (image) from the WhatsApp Cloud API by media ID.

    Two-step process:
      1. GET the media metadata to retrieve the download URL.
      2. GET the actual binary payload from that URL.

    Args:
        media_id: The WhatsApp Cloud API media ID (from the webhook payload).

    Returns:
        Raw image bytes on success, or None on failure.
    """
    if not META_ACCESS_TOKEN:
        logger.warning("META_ACCESS_TOKEN not set; cannot download media")
        return None

    headers = {"Authorization": f"Bearer {META_ACCESS_TOKEN}"}

    try:
        # Step 1 — Resolve media ID to a download URL.
        meta_url = f"{_GRAPH_API_BASE}/{media_id}"
        resp = requests.get(meta_url, headers=headers, timeout=10)
        resp.raise_for_status()
        download_url = resp.json().get("url")
        if not download_url:
            logger.error("No download URL returned for media_id=%s", media_id)
            return None

        # Step 2 — Download the binary image.
        img_resp = requests.get(download_url, headers=headers, timeout=15)
        img_resp.raise_for_status()
        logger.info(
            "Downloaded media %s (%d bytes)", media_id, len(img_resp.content)
        )
        return img_resp.content

    except requests.RequestException as exc:
        logger.error("Media download failed for %s: %s", media_id, exc)
        return None


def download_meta_image(media_id: str) -> bytes | None:
    """Download an image from the Meta Graph API by media ID.

    This is the public API used by the webhook image pipeline.
    Delegates to download_whatsapp_media() which performs the two-step
    Graph API resolution (media ID → download URL → raw bytes).

    Args:
        media_id: The WhatsApp Cloud API media ID.

    Returns:
        Raw image bytes on success, or None on failure.
    """
    return download_whatsapp_media(media_id)
