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
#   │    ┌────┴─────────────────────┐                          │
#   │    │ text msg?                │ image msg?               │
#   │    │   │                      │   │                      │
#   │    │ extract_urls()           │ download_media()         │
#   │    │   │                      │   │                      │
#   │    │ scan_url() × N           │ scan_image() (QR decode) │
#   │    │   │                      │   │                      │
#   │    └───┬──────────────────────┘   │                      │
#   │        │                          │                      │
#   │    Verdict: BLOCKED (🚨) or SAFE (✅)                    │
#   │        │                                                 │
#   │    send_whatsapp_reply()  ← response to user             │
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

from dotenv import load_dotenv
from fastapi import FastAPI, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from meta_client import (
    META_VERIFY_TOKEN,
    download_meta_image,
    download_whatsapp_media,
    send_whatsapp_reply,
)
from scanner import extract_urls, scan_image, scan_url

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
# IMAGE MESSAGE PROCESSING
# ─────────────────────────────────────────────────────────────────────────────


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
    """
    urls = extract_urls(text)

    if not urls:
        return (
            "SAFE",
            "\u2705 KAVACH: No threats detected in this message.",
            [],
        )

    results = [scan_url(u) for u in urls]
    has_threat = any(r["verdict"] == "PHISHING" for r in results)

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
async def webhook_whatsapp(request: Request) -> dict:
    """Process incoming WhatsApp messages from the Meta Cloud API.

    The Meta webhook POST payload follows this structure:
    {
      "object": "whatsapp_business_account",
      "entry": [{
        "changes": [{
          "value": {
            "messages": [{
              "from": "919876543210",
              "type": "text" | "image",
              "text": { "body": "..." },
              "image": { "id": "media_id_123", "mime_type": "image/jpeg" }
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
                    logger.info(
                        "QR verdict for %s: %s (%d QR codes found)",
                        sender,
                        qr_verdict,
                        qr_result.get("qr_codes_found", 0),
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
async def ingest_telemetry(payload: TelemetryPayload) -> dict:
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

    return {
        "status": "logged",
        "report_id": report_id,
        "message": "Threat telemetry ingested successfully.",
    }
