# =============================================================================
# KAVACH — main.py (Omni-Scanner — Production-Ready FastAPI Microservice)
# =============================================================================
#
# Zero-Trust SMS/WhatsApp phishing interceptor for SBI YONO.
#
# Architecture:
#   ┌──────────────────────────────────────────────────────────┐
#   │  Meta Cloud API (WhatsApp Business Platform)             │
#   │         │                                                │
#   │   GET  /webhook/whatsapp  ← Verification handshake      │
#   │   POST /webhook/whatsapp  ← Incoming messages            │
#   │         │                                                │
#   │    ┌────┴──────────────────┬──────────────┬──────────┐   │
#   │    │ text msg?             │ image msg?   │ document?│   │
#   │    │   │                   │   │          │   │      │   │
#   │    │ extract_urls()        │ QR decode    │ APK check│   │
#   │    │   │                   │   │          │   │      │   │
#   │    │ scan_url() × N        │ scan_image() │ BLOCK APK│   │
#   │    │   │                   │   │          │   │      │   │
#   │    └───┴───────────────────┴───┘──────────┴───┘      │   │
#   │        │                                             │   │
#   │    Verdict: BLOCKED (🚨) or SAFE (✅)                │   │
#   │        │                                             │   │
#   │    send_whatsapp_reply()  ← response to user         │   │
#   └──────────────────────────────────────────────────────────┘
#
# Run:
#   python -m uvicorn main:app --reload --port 8080
#
# Environment Variables (see .env):
#   META_VERIFY_TOKEN     — webhook verification token (you define this)
#   META_ACCESS_TOKEN     — WhatsApp Cloud API bearer token
#   META_PHONE_NUMBER_ID  — your WhatsApp Business phone number ID
# =============================================================================

from __future__ import annotations

import logging
import os
from datetime import datetime, timezone

import requests
from dotenv import load_dotenv
from fastapi import BackgroundTasks, FastAPI, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from meta_client import (
    META_ACCESS_TOKEN,
    META_VERIFY_TOKEN,
    download_meta_image,
    download_whatsapp_media,
    send_whatsapp_reply,
)
from scanner import extract_urls, scan_image, scan_url
from takedown_automation import execute_takedown_protocol

# ─────────────────────────────────────────────────────────────────────────────
# ENVIRONMENT & LOGGING
# ─────────────────────────────────────────────────────────────────────────────

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s │ %(name)-22s │ %(levelname)-7s │ %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("kavach.main")

# Meta / WhatsApp Cloud API configuration is centralized in meta_client.py.
# META_VERIFY_TOKEN, send_whatsapp_reply, and download_whatsapp_media are
# imported from there. See .env for credential setup.

GRAPH_API_BASE = "https://graph.facebook.com/v18.0"
SIGNATURE_SCAN_BYTES = 2048
SIGNATURE_SCAN_TIMEOUT = (2, 3)
ANDROID_ZIP_MAGIC = bytes.fromhex("50 4B 03 04")
DEX_MAGIC = bytes.fromhex("64 65 78 0A")

# ─────────────────────────────────────────────────────────────────────────────
# APP INIT
# ─────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="KAVACH Omni-Scanner",
    description=(
        "Production-ready Pre-Click Interceptor for the KAVACH Zero-Trust "
        "banking security pipeline.  Handles real Meta Cloud API webhooks, "
        "scans text URLs via heuristics, and decodes malicious QR codes "
        "hidden in images."
    ),
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─────────────────────────────────────────────────────────────────────────────
# PYDANTIC MODELS
# ─────────────────────────────────────────────────────────────────────────────


class IncomingMessage(BaseModel):
    """Simple payload for the direct /scan/text testing endpoint."""

    user_id: str = Field(
        ...,
        min_length=1,
        description="Unique identifier of the sender.",
        examples=["usr_91_9876543210"],
    )
    message_text: str = Field(
        ...,
        min_length=1,
        description="Raw message body that may contain URLs.",
        examples=[
            "Dear customer, update KYC now: https://sbi-kyc.top/verify"
        ],
    )


class ScanVerdict(BaseModel):
    """Structured response returned to the gateway / Flutter client."""

    status: str = Field(..., description="Overall verdict: BLOCKED or SAFE.")
    alert: str = Field(..., description="Human-readable alert message.")
    scanned_urls: list[dict] | None = Field(
        default=None,
        description="Per-URL scan results (included for observability).",
    )
    qr_scan: dict | None = Field(
        default=None,
        description="QR code scan results (if an image was processed).",
    )
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO-8601 timestamp of the scan.",
    )


# ─────────────────────────────────────────────────────────────────────────────
# META WHATSAPP CLOUD API
# ─────────────────────────────────────────────────────────────────────────────
# send_whatsapp_reply() and download_whatsapp_media() are imported from
# meta_client.py — the single source of truth for all Meta Graph API logic.


# ─────────────────────────────────────────────────────────────────────────────
# DOCUMENT SIDELOAD TELEMETRY
# ─────────────────────────────────────────────────────────────────────────────


def _log_document_threat(sender: str, detected_name: str) -> None:
    """Background task: log a blocked document sideload attempt.

    In production this would persist to the SIEM / threat-intel data lake.
    For the MVP we emit a prominent console banner for demo visibility.
    """
    banner = (
        "\n"
        "+============================================================+\n"
        "|     !! DOCUMENT SIDELOAD BLOCKED !!                        |\n"
        "+============================================================+\n"
        f"|  Sender   : {sender:<42}|\n"
        f"|  File     : {detected_name:<42}|\n"
        f"|  Action   : {'AUTO-BLOCKED + USER WARNED':<42}|\n"
        f"|  Time     : {datetime.now(timezone.utc).isoformat():<42}|\n"
        "+============================================================+\n"
    )
    print(banner)
    logger.warning(
        "[TELEMETRY] Document sideload blocked: sender=%s file=%s",
        sender,
        detected_name,
    )


# ─────────────────────────────────────────────────────────────────────────────
# IMAGE MESSAGE PROCESSING
# ─────────────────────────────────────────────────────────────────────────────


def _resolve_whatsapp_media_url(media_id: str, auth_token: str) -> str | None:
    """Resolve a WhatsApp media ID into Meta's short-lived download URL."""
    if not media_id or not auth_token:
        return None

    headers = {"Authorization": f"Bearer {auth_token}"}
    try:
        response = requests.get(
            f"{GRAPH_API_BASE}/{media_id}",
            headers=headers,
            timeout=SIGNATURE_SCAN_TIMEOUT,
        )
        response.raise_for_status()
        media_url = response.json().get("url")
        if not media_url:
            logger.warning("No media URL returned for document media_id=%s", media_id)
            return None
        return media_url
    except requests.exceptions.Timeout:
        logger.warning("Timed out resolving document media_id=%s", media_id)
        return None
    except requests.RequestException as exc:
        logger.warning("Unable to resolve document media_id=%s: %s", media_id, exc)
        return None


def verify_file_signature(file_url: str, auth_token: str) -> dict:
    """Inspect the first bytes of a WhatsApp file without downloading it."""
    if not file_url or not auth_token:
        return {
            "verdict": "SIGNATURE_UNAVAILABLE",
            "signature": None,
            "hex_prefix": "",
        }

    headers = {
        "Authorization": f"Bearer {auth_token}",
        "Range": f"bytes=0-{SIGNATURE_SCAN_BYTES - 1}",
    }

    try:
        with requests.get(
            file_url,
            headers=headers,
            stream=True,
            timeout=SIGNATURE_SCAN_TIMEOUT,
        ) as response:
            response.raise_for_status()
            header_bytes = b""
            for chunk in response.iter_content(chunk_size=SIGNATURE_SCAN_BYTES):
                if chunk:
                    header_bytes += chunk
                    break

        header_bytes = header_bytes[:SIGNATURE_SCAN_BYTES]
        hex_prefix = header_bytes[:16].hex(" ").upper()

        if header_bytes.startswith(DEX_MAGIC):
            return {
                "verdict": "EXECUTABLE_SIGNATURE",
                "signature": "DEX",
                "hex_prefix": hex_prefix,
            }

        if header_bytes.startswith(ANDROID_ZIP_MAGIC):
            return {
                "verdict": "EXECUTABLE_SIGNATURE",
                "signature": "ZIP_APK_OR_JAR",
                "hex_prefix": hex_prefix,
            }

        return {
            "verdict": "NO_EXECUTABLE_SIGNATURE",
            "signature": None,
            "hex_prefix": hex_prefix,
        }
    except requests.exceptions.Timeout:
        logger.warning("Timed out during file signature scan for %s", file_url)
    except requests.RequestException as exc:
        logger.warning("File signature scan failed for %s: %s", file_url, exc)

    return {
        "verdict": "SIGNATURE_UNAVAILABLE",
        "signature": None,
        "hex_prefix": "",
    }


def _metadata_claims_safe_document(filename: str, mime_type: str) -> bool:
    """Return True when WhatsApp metadata presents the file as harmless."""
    safe_extensions = (
        ".pdf",
        ".png",
        ".jpg",
        ".jpeg",
        ".webp",
        ".gif",
        ".txt",
        ".doc",
        ".docx",
        ".xls",
        ".xlsx",
        ".ppt",
        ".pptx",
    )
    safe_mime_prefixes = ("image/", "text/")
    safe_mime_types = {
        "application/pdf",
        "application/msword",
        "application/vnd.ms-excel",
        "application/vnd.ms-powerpoint",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/octet-stream",
    }

    return (
        any(filename.endswith(ext) for ext in safe_extensions)
        or any(mime_type.startswith(prefix) for prefix in safe_mime_prefixes)
        or mime_type in safe_mime_types
    )


def process_image_message(media_id: str) -> dict:
    """Download an image from WhatsApp and scan it for malicious QR codes.

    Uses download_meta_image() from meta_client.py which performs the
    two-step Graph API resolution (media ID → URL → raw bytes), then
    feeds the image through the pyzbar QR decoder → scan_url() pipeline.

    Args:
        media_id: The WhatsApp Cloud API media ID.

    Returns:
        A scan_image() result dict.
    """
    image_bytes = download_meta_image(media_id)
    if image_bytes is None:
        return {
            "source": "QR_SCAN",
            "qr_codes_found": 0,
            "decoded_payloads": [],
            "scanned_urls": [],
            "verdict": "SAFE",
            "rule": None,
            "error": "Unable to download image from WhatsApp CDN",
        }

    return scan_image(image_bytes)


# ─────────────────────────────────────────────────────────────────────────────
# TEXT MESSAGE PROCESSING
# ─────────────────────────────────────────────────────────────────────────────


def process_text_message(text: str) -> tuple[str, str, list[dict]]:
    """Extract URLs from text and scan them.

    Returns:
        (status, alert_message, scanned_urls_list)

    Status is STRICTLY BINARY:
      - ``"BLOCKED"``  — at least one URL is confirmed malicious
      - ``"SAFE"``     — no threats detected
    """
    urls = extract_urls(text)

    if not urls:
        return (
            "SAFE",
            "\u2705 KAVACH: No threats detected in this message.",
            [],
        )

    results = [scan_url(u) for u in urls]
    has_threat = any(r["verdict"] == "BLOCKED" for r in results)

    if has_threat:
        return (
            "BLOCKED",
            (
                "\U0001f6a8 KAVACH ALERT: Phishing link detected. "
                "This domain is attempting to impersonate SBI. Do not click."
            ),
            results,
        )

    return (
        "SAFE",
        "\u2705 KAVACH: No threats detected in this message.",
        results,
    )


# ─────────────────────────────────────────────────────────────────────────────
# ENDPOINTS — Health
# ─────────────────────────────────────────────────────────────────────────────


@app.get("/health")
async def health_check() -> dict:
    """Liveness probe for orchestrators (K8s, ECS, etc.)."""
    return {
        "service": "kavach-omni-scanner",
        "version": "2.0.0",
        "status": "operational",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ─────────────────────────────────────────────────────────────────────────────
# ENDPOINTS — Meta WhatsApp Webhook (GET = verification, POST = messages)
# ─────────────────────────────────────────────────────────────────────────────


@app.get("/webhook/whatsapp")
async def webhook_verify(
    request: Request,
    # Meta sends these as query parameters during webhook registration.
    hub_mode: str | None = Query(None, alias="hub.mode"),
    hub_verify_token: str | None = Query(None, alias="hub.verify_token"),
    hub_challenge: str | None = Query(None, alias="hub.challenge"),
) -> PlainTextResponse:
    """Meta Cloud API webhook verification handshake.

    When you register a webhook URL in the Meta App Dashboard, Meta sends
    a GET request with three query parameters:
      - hub.mode          = "subscribe"
      - hub.verify_token  = the token you configured in the dashboard
      - hub.challenge     = a random string Meta expects you to echo back

    If the verify_token matches, return hub.challenge as plain text with
    a 200 status.  Otherwise return 403.
    """
    logger.info(
        "Webhook verification: mode=%s token=%s challenge=%s",
        hub_mode,
        hub_verify_token,
        hub_challenge,
    )

    if hub_mode == "subscribe" and hub_verify_token == META_VERIFY_TOKEN:
        logger.info("✅ Webhook verification PASSED")
        return PlainTextResponse(content=hub_challenge or "", status_code=200)

    logger.warning("❌ Webhook verification FAILED — token mismatch")
    return PlainTextResponse(content="Forbidden", status_code=403)


@app.post("/webhook/whatsapp")
async def webhook_whatsapp(
    request: Request,
    background_tasks: BackgroundTasks,
) -> dict:
    """Process incoming WhatsApp messages from the Meta Cloud API.

    The Meta webhook POST payload follows this structure:
    {
      "object": "whatsapp_business_account",
      "entry": [{
        "changes": [{
          "value": {
            "messages": [{
              "from": "919876543210",
              "type": "text" | "image" | "document",
              "text": { "body": "..." },
              "image": { "id": "media_id_123", "mime_type": "image/jpeg" },
              "document": {
                "id": "media_id_456",
                "filename": "update.apk",
                "mime_type": "application/vnd.android.package-archive"
              }
            }]
          }
        }]
      }]
    }

    This handler extracts the message, routes to the appropriate scanner
    pipeline (text or image), and fires an auto-reply to the sender.
    """
    body = await request.json()

    # ── Validate top-level structure ──
    if body.get("object") != "whatsapp_business_account":
        logger.debug("Ignoring non-WhatsApp webhook payload")
        return {"status": "ignored"}

    # ── Walk the nested entry → changes → value → messages path ──
    for entry in body.get("entry", []):
        for change in entry.get("changes", []):
            value = change.get("value", {})
            messages = value.get("messages", [])

            for msg in messages:
                sender = msg.get("from", "unknown")
                msg_type = msg.get("type", "unknown")

                logger.info(
                    "📩 Incoming %s message from %s", msg_type, sender
                )

                # ── Route: TEXT message → Pipeline 1 (URL heuristics) ──
                if msg_type == "text":
                    text_body = msg.get("text", {}).get("body", "")
                    if not text_body:
                        continue

                    status, alert, scanned_urls = process_text_message(
                        text_body
                    )
                    send_whatsapp_reply(sender, alert)

                    # ── Takedown Protocol: fire in background for every
                    #    PHISHING URL so the reply is never delayed ──
                    if status == "BLOCKED":
                        for sr in scanned_urls:
                            if sr.get("verdict") == "PHISHING":
                                phishing_url = sr.get("url", "")
                                if phishing_url:
                                    logger.info(
                                        "🚨 Queueing takedown for %s",
                                        phishing_url,
                                    )
                                    background_tasks.add_task(
                                        execute_takedown_protocol,
                                        phishing_url,
                                    )

                    logger.info(
                        "Verdict for %s: %s (%d URLs scanned)",
                        sender,
                        status,
                        len(scanned_urls),
                    )

                # ── Route: IMAGE message → Pipeline 2 (QR decode) ──
                elif msg_type == "image":
                    media_id = msg.get("image", {}).get("id", "")
                    if not media_id:
                        continue

                    qr_result = process_image_message(media_id)
                    qr_verdict = qr_result.get("verdict", "SAFE")

                    if qr_verdict == "PHISHING":
                        alert = (
                            "\U0001f6a8 KAVACH ALERT: Malicious QR code "
                            "detected in this image! The embedded link is "
                            "a phishing attempt. Do NOT scan this QR code."
                        )
                    else:
                        alert = (
                            "\u2705 KAVACH: No QR codes or threats found "
                            "in this image."
                        )

                    send_whatsapp_reply(sender, alert)

                    # ── Takedown Protocol for QR-embedded phishing URLs ──
                    if qr_verdict == "PHISHING":
                        for sr in qr_result.get("scanned_urls", []):
                            if sr.get("verdict") == "PHISHING":
                                phishing_url = sr.get("url", "")
                                if phishing_url:
                                    logger.info(
                                        "🚨 Queueing takedown (QR) for %s",
                                        phishing_url,
                                    )
                                    background_tasks.add_task(
                                        execute_takedown_protocol,
                                        phishing_url,
                                    )

                    logger.info(
                        "QR verdict for %s: %s (%d QR codes found)",
                        sender,
                        qr_verdict,
                        qr_result.get("qr_codes_found", 0),
                    )

                # ── Route: DOCUMENT message → Pipeline 3 (APK sideload block) ──
                elif msg_type == "document":
                    doc_payload = msg.get("document", {})
                    media_id = (doc_payload.get("id") or "").strip()
                    filename = (doc_payload.get("filename") or "").strip().lower()
                    mime_type = (doc_payload.get("mime_type") or "").strip().lower()

                    # Dangerous Android package extensions
                    DANGEROUS_EXTENSIONS = (".apk", ".xapk", ".jar", ".dex")
                    # Meta / Android MIME types for installable packages
                    DANGEROUS_MIME_TYPES = {
                        "application/vnd.android.package-archive",
                        "application/java-archive",
                        "application/x-java-archive",
                        "application/dex",
                    }

                    signature_scan = {
                        "verdict": "SIGNATURE_UNAVAILABLE",
                        "signature": None,
                        "hex_prefix": "",
                    }
                    if media_id and META_ACCESS_TOKEN:
                        file_url = _resolve_whatsapp_media_url(
                            media_id,
                            META_ACCESS_TOKEN,
                        )
                        if file_url:
                            signature_scan = verify_file_signature(
                                file_url,
                                META_ACCESS_TOKEN,
                            )
                    elif media_id:
                        logger.warning(
                            "META_ACCESS_TOKEN not set; skipping magic-byte scan for %s",
                            media_id,
                        )

                    is_disguised_payload = (
                        signature_scan.get("verdict") == "EXECUTABLE_SIGNATURE"
                        and _metadata_claims_safe_document(filename, mime_type)
                    )

                    is_dangerous = (
                        is_disguised_payload
                        or any(
                            filename.endswith(ext) for ext in DANGEROUS_EXTENSIONS
                        )
                        or mime_type in DANGEROUS_MIME_TYPES
                    )

                    if is_dangerous:
                        detected_name = filename or mime_type or "unknown file"
                        if is_disguised_payload:
                            alert = (
                                "\U0001f6a8 BLOCKED: MALICIOUS_PAYLOAD_DISGUISED. "
                                "This file claims to be a safe document, but "
                                "KAVACH found Android executable bytes inside. "
                                "Do not open it or install anything from it."
                            )
                        else:
                            alert = (
                                "\U0001f6a8 BLOCKED: KAVACH detected a malicious "
                                "Android installation file (.apk). Official SBI "
                                "apps are ONLY available via the Google Play Store. "
                                "Never download app files directly from WhatsApp."
                            )
                        send_whatsapp_reply(sender, alert)

                        # ── Telemetry: log the sideload attempt ──
                        background_tasks.add_task(
                            _log_document_threat,
                            sender,
                            detected_name,
                        )

                        logger.warning(
                            "\U0001f6a8 DOCUMENT SIDELOAD BLOCKED: "
                            "file=%s mime=%s signature=%s hex=%s from=%s",
                            filename or "(no filename)",
                            mime_type or "(no mime)",
                            signature_scan.get("signature") or "(none)",
                            signature_scan.get("hex_prefix") or "(unavailable)",
                            sender,
                        )
                    else:
                        logger.info(
                            "Document from %s is safe (file=%s, mime=%s)",
                            sender,
                            filename or "(no filename)",
                            mime_type or "(no mime)",
                        )

                else:
                    logger.debug(
                        "Unsupported message type '%s' from %s — skipping",
                        msg_type,
                        sender,
                    )

    # Meta expects a 200 response to acknowledge receipt.
    return {"status": "processed"}


# ─────────────────────────────────────────────────────────────────────────────
# ENDPOINTS — Direct scan (testing / Flutter client)
# ─────────────────────────────────────────────────────────────────────────────


@app.post(
    "/scan/text",
    response_model=ScanVerdict,
    summary="Directly scan a text message (testing endpoint)",
)
async def scan_text_direct(payload: IncomingMessage) -> ScanVerdict:
    """Scan a text message directly without the Meta webhook wrapper.

    Use this endpoint for testing from curl, Postman, or the Flutter client.
    """
    status, alert, scanned_urls = process_text_message(payload.message_text)
    return ScanVerdict(
        status=status,
        alert=alert,
        scanned_urls=scanned_urls,
    )


@app.post(
    "/scan/image",
    summary="Directly scan an uploaded image for malicious QR codes",
)
async def scan_image_direct(request: Request) -> dict:
    """Upload a raw image and scan it for QR codes containing phishing URLs.

    Send the image as the raw request body with Content-Type: image/png
    (or image/jpeg).  Use this for testing without the Meta media pipeline.
    """
    image_bytes = await request.body()
    if not image_bytes:
        return {
            "status": "error",
            "message": "No image data received in request body.",
        }

    qr_result = scan_image(image_bytes)
    overall_verdict = qr_result.get("verdict", "SAFE")

    if overall_verdict == "PHISHING":
        alert = (
            "\U0001f6a8 KAVACH ALERT: Malicious QR code detected! "
            "The embedded link is a phishing attempt."
        )
    else:
        alert = "\u2705 KAVACH: No malicious QR codes detected in this image."

    return {
        "status": "BLOCKED" if overall_verdict == "PHISHING" else "SAFE",
        "alert": alert,
        "qr_scan": qr_result,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ─────────────────────────────────────────────────────────────────────────────
# REPORT INGESTION (from YONO Shield Flutter client)
# ─────────────────────────────────────────────────────────────────────────────


class FraudReport(BaseModel):
    """Payload sent by the YONO Shield app's reportFraudSilently() function."""

    device_id: str
    package_name: str
    threat_type: str
    timestamp: str


@app.post(
    "/v1/report",
    summary="Ingest a silent fraud report from the YONO Shield client",
)
async def ingest_fraud_report(report: FraudReport) -> dict:
    """Accept and acknowledge a fraud report from the mobile client.

    In production this would persist to a threat-intelligence data lake.
    For the MVP we simply acknowledge receipt.
    """
    logger.info(
        "\U0001f4cb Fraud report: device=%s pkg=%s type=%s",
        report.device_id,
        report.package_name,
        report.threat_type,
    )
    return {
        "status": "received",
        "report_id": f"RPT-{abs(hash(report.device_id + report.timestamp)) % 10**8:08d}",
        "message": "Fraud report ingested successfully.",
    }


# ─────────────────────────────────────────────────────────────────────────────
# TELEMETRY BRIDGE (from YONO Shield Android client)
# ─────────────────────────────────────────────────────────────────────────────


class TelemetryPayload(BaseModel):
    """Threat telemetry payload sent by the YONO Shield mobile client."""

    device_id: str = Field(..., description="Hashed device identifier.")
    package_name: str = Field(..., description="Package name of the threat.")
    threat_type: str = Field(
        ..., description="Classification: TROJAN, SIGNATURE_MISMATCH, etc."
    )
    timestamp: str = Field(..., description="ISO-8601 detection timestamp.")


@app.post(
    "/api/telemetry",
    summary="Ingest real-time threat telemetry from the YONO Shield client",
)
async def ingest_telemetry(
    payload: TelemetryPayload,
    background_tasks: BackgroundTasks,
) -> dict:
    """Accept and log threat telemetry from the YONO Shield mobile client.

    This is the enterprise Telemetry Bridge endpoint.  In production this
    would stream events to a SIEM / data lake (Splunk, ELK, BigQuery).
    For the MVP we log a prominent ASCII-art banner to the console.
    """
    # ── ASCII-art banner for demo visibility ──
    banner = (
        "\n"
        "+============================================================+\n"
        "|        !! NEW THREAT LOGGED !!                             |\n"
        "+============================================================+\n"
        f"|  Device    : {payload.device_id:<42}|\n"
        f"|  Package   : {payload.package_name:<42}|\n"
        f"|  Threat    : {payload.threat_type:<42}|\n"
        f"|  Timestamp : {payload.timestamp:<42}|\n"
        "+============================================================+\n"
    )
    print(banner)

    logger.info(
        "[ALERT] TELEMETRY: device=%s pkg=%s threat=%s ts=%s",
        payload.device_id,
        payload.package_name,
        payload.threat_type,
        payload.timestamp,
    )

    report_id = f"TEL-{abs(hash(payload.device_id + payload.timestamp)) % 10**8:08d}"

    # ── Takedown Protocol: auto-trigger for PHISHING telemetry ──
    # The threat_type from the Flutter client may encode the malicious
    # package name or URL.  If it contains "PHISHING", fire the pipeline.
    if "PHISHING" in payload.threat_type.upper():
        # The package_name field in phishing telemetry often carries the URL
        target_url = payload.package_name
        if not target_url.startswith("http"):
            target_url = f"https://{target_url}"
        logger.info(
            "🚨 Queueing takedown from telemetry for %s", target_url
        )
        background_tasks.add_task(execute_takedown_protocol, target_url)

    return {
        "status": "logged",
        "report_id": report_id,
        "message": "Threat telemetry ingested successfully.",
        "takedown_queued": "PHISHING" in payload.threat_type.upper(),
    }
