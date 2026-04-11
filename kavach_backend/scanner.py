# =============================================================================
# KAVACH — scanner.py (Omni-Scanner: URL Heuristics + QR Decoder)
# =============================================================================
#
# Stateless multi-modal scanner for the KAVACH Pre-Click Interceptor.
#
# Pipelines:
#   Pipeline 1 — Text:  raw SMS text ──► extract_urls() ──► scan_url()
#   Pipeline 2 — Image: image bytes  ──► scan_image()   ──► decode QR
#                                                        ──► scan_url()
#   Pipeline 3 — OCR:   (stub) screenshot ──► OCR text ──► extract_urls()
#
# Each scan_url() call runs the URL through a chain of heuristic rules.
# If ANY rule fires, the URL is flagged as PHISHING immediately.
# If all rules pass, the URL is marked SAFE.
# =============================================================================

from __future__ import annotations

import io
import logging
import re
from urllib.parse import urlparse

from PIL import Image
from pyzbar import pyzbar

logger = logging.getLogger("kavach.scanner")

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION — Whitelists, blacklists, and pattern tables
# ─────────────────────────────────────────────────────────────────────────────

# Official SBI domains that are SAFE and must never be flagged.
WHITELISTED_DOMAINS: set[str] = {
    "onlinesbi.sbi",
    "sbiyono.sbi",
    "sbi.co.in",
    "bank.sbi",
    "www.onlinesbi.sbi",
    "www.sbiyono.sbi",
    "www.sbi.co.in",
    "www.bank.sbi",
}

# Brand keywords — if a domain contains any of these but is NOT whitelisted,
# it's almost certainly a brand-spoofing attempt.
BRAND_KEYWORDS: list[str] = [
    "sbi",
    "yono",
    "statebank",
]

# Common homoglyph / typo-squatting patterns used by phishing kits.
HOMOGLYPH_PATTERNS: list[str] = [
    "yon0",        # o → 0
    "0nlinesbi",   # O → 0
    "sbi-kyc",     # fake KYC subdomain trick
    "yonosbi",     # smashed-together impersonation
    "sb1",         # i → 1
    "y0no",        # o → 0
    "stat3bank",   # e → 3
]

# Top-level domains overwhelmingly associated with disposable phishing sites.
HIGH_RISK_TLDS: set[str] = {
    ".xyz",
    ".top",
    ".click",
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
    ".buzz",
    ".rest",
}

# ─────────────────────────────────────────────────────────────────────────────
# PIPELINE 1 — URL EXTRACTOR
# ─────────────────────────────────────────────────────────────────────────────

# Robust regex that captures http / https URLs including paths, query strings,
# and fragments, while avoiding trailing punctuation (period, comma, etc.).
_URL_PATTERN = re.compile(
    r"https?://"                # scheme
    r"[^\s<>\"'{}|\\^`\[\]]+"  # everything until whitespace or special chars
)


def extract_urls(text: str) -> list[str]:
    """Pull all HTTP/HTTPS URLs out of a raw message string.

    Args:
        text: The raw SMS / WhatsApp message body.

    Returns:
        A deduplicated list of URLs found in the text, preserving order.
    """
    raw_matches = _URL_PATTERN.findall(text)

    # Strip trailing punctuation that the regex may have captured
    # (e.g. "http://evil.xyz." or "http://evil.xyz,check").
    cleaned: list[str] = []
    seen: set[str] = set()
    for url in raw_matches:
        url = url.rstrip(".,;:!?)\u2026")
        if url not in seen:
            seen.add(url)
            cleaned.append(url)

    return cleaned


# ─────────────────────────────────────────────────────────────────────────────
# HEURISTIC RULES ENGINE
# ─────────────────────────────────────────────────────────────────────────────

def _check_brand_spoofing(domain: str) -> str | None:
    """Rule 1 — Brand Spoofing.

    Fires if the domain contains a protected brand keyword but is NOT
    in the official whitelist.
    """
    for keyword in BRAND_KEYWORDS:
        if keyword in domain and domain not in WHITELISTED_DOMAINS:
            return (
                f"BRAND_SPOOFING: domain contains '{keyword}' "
                f"but is not an official SBI domain"
            )
    return None


def _check_homoglyphs(domain: str) -> str | None:
    """Rule 2 — Homoglyph / Typo-Squatting Detection.

    Fires if the domain contains any known homoglyph or typo pattern.
    """
    for pattern in HOMOGLYPH_PATTERNS:
        if pattern in domain:
            return (
                f"HOMOGLYPH: domain contains suspicious pattern '{pattern}'"
            )
    return None


def _check_high_risk_tld(domain: str) -> str | None:
    """Rule 3 — High-Risk TLD.

    Fires if the domain ends with a TLD known for abuse.
    """
    for tld in HIGH_RISK_TLDS:
        if domain.endswith(tld):
            return f"HIGH_RISK_TLD: domain uses suspicious TLD '{tld}'"
    return None


# Ordered chain of heuristic rules.  Each function returns a reason string
# if the rule fires, or None if the URL passes that check.
_HEURISTIC_CHAIN = [
    _check_brand_spoofing,
    _check_homoglyphs,
    _check_high_risk_tld,
]


def scan_url(url: str) -> dict:
    """Run a URL through the full heuristic rules engine.

    Args:
        url: A single HTTP/HTTPS URL string.

    Returns:
        A dict with keys:
          - url:     the original URL
          - domain:  the extracted domain (netloc)
          - verdict: "PHISHING" or "SAFE"
          - rule:    human-readable reason (only present when PHISHING)
    """
    parsed = urlparse(url)
    domain = parsed.netloc.lower().strip()
    if not domain:
        return {
            "url": url,
            "domain": "",
            "verdict": "PHISHING",
            "rule": "MALFORMED_URL: unable to extract domain",
        }

    # Strip port number if present (e.g. evil.xyz:8080 → evil.xyz)
    domain_no_port = domain.split(":")[0]

    # Run each heuristic rule in order — short-circuit on first hit.
    for rule_fn in _HEURISTIC_CHAIN:
        reason = rule_fn(domain_no_port)
        if reason is not None:
            return {
                "url": url,
                "domain": domain_no_port,
                "verdict": "PHISHING",
                "rule": reason,
            }

    return {
        "url": url,
        "domain": domain_no_port,
        "verdict": "SAFE",
    }


# ─────────────────────────────────────────────────────────────────────────────
# PIPELINE 2 — QR CODE IMAGE SCANNER
# ─────────────────────────────────────────────────────────────────────────────

def scan_image(image_source: str | bytes | io.IOBase) -> dict:
    """Decode QR codes from an image and scan any embedded URLs.

    Accepts a file path, raw bytes, or a file-like object.  Gracefully
    handles non-QR images (selfies, memes, etc.) by returning a SAFE
    verdict with zero decoded payloads.

    Args:
        image_source: One of:
          - str:   absolute file path to a JPEG/PNG image
          - bytes: raw image bytes (e.g. downloaded from Meta CDN)
          - file-like: any readable binary stream

    Returns:
        {
            "source": "QR_SCAN",
            "qr_codes_found": int,
            "decoded_payloads": [ { "data": str, "type": str } ],
            "scanned_urls": [ scan_url() result for each URL payload ],
            "verdict": "PHISHING" | "SAFE",
            "rule": str | None
        }
    """
    try:
        # ── Load image ──
        if isinstance(image_source, str):
            img = Image.open(image_source)
        elif isinstance(image_source, bytes):
            img = Image.open(io.BytesIO(image_source))
        else:
            img = Image.open(image_source)

        # ── Decode all barcodes / QR codes ──
        decoded_objects = pyzbar.decode(img)

    except Exception as exc:
        # Graceful fallback: corrupt image, unsupported format, etc.
        logger.warning("Image decode failed: %s", exc)
        return {
            "source": "QR_SCAN",
            "qr_codes_found": 0,
            "decoded_payloads": [],
            "scanned_urls": [],
            "verdict": "SAFE",
            "rule": None,
            "error": f"Image processing failed: {type(exc).__name__}",
        }

    if not decoded_objects:
        # No QR codes found — probably a selfie or regular photo.
        return {
            "source": "QR_SCAN",
            "qr_codes_found": 0,
            "decoded_payloads": [],
            "scanned_urls": [],
            "verdict": "SAFE",
            "rule": None,
        }

    # ── Extract payloads and scan any URLs ──
    payloads: list[dict] = []
    url_results: list[dict] = []

    for obj in decoded_objects:
        try:
            data = obj.data.decode("utf-8", errors="replace")
        except Exception:
            data = str(obj.data)

        payload_entry = {
            "data": data,
            "type": obj.type,  # e.g. "QRCODE", "EAN13", etc.
        }
        payloads.append(payload_entry)

        # If the QR payload is a URL, run it through the heuristic engine.
        urls_in_payload = extract_urls(data)
        for url in urls_in_payload:
            result = scan_url(url)
            result["source"] = "QR_CODE"
            url_results.append(result)

    has_threat = any(r["verdict"] == "PHISHING" for r in url_results)

    return {
        "source": "QR_SCAN",
        "qr_codes_found": len(decoded_objects),
        "decoded_payloads": payloads,
        "scanned_urls": url_results,
        "verdict": "PHISHING" if has_threat else "SAFE",
        "rule": (
            "QR_PHISHING: QR code contains a malicious URL"
            if has_threat
            else None
        ),
    }


# ─────────────────────────────────────────────────────────────────────────────
# PIPELINE 3 — SCREENSHOT OCR (Stub — Layer 3+)
# ─────────────────────────────────────────────────────────────────────────────

# async def run_ocr_on_screenshot(image: bytes | str) -> dict:
#     """Extract text from a screenshot using OCR, then scan for phishing URLs.
#
#     This pipeline targets a common social-engineering vector where attackers
#     send SCREENSHOTS of phishing messages instead of the text itself,
#     defeating text-based URL extraction.
#
#     Implementation plan:
#       1. Load image with PIL / OpenCV.
#       2. Pre-process: greyscale, contrast enhancement, de-skew.
#       3. Run Tesseract OCR via pytesseract.image_to_string().
#       4. Feed extracted text into extract_urls() → scan_url() pipeline.
#       5. Return combined verdict with OCR confidence score.
#
#     Requires:
#       - pytesseract (pip install pytesseract)
#       - Tesseract OCR engine installed on host (apt install tesseract-ocr)
#       - opencv-python for pre-processing (optional but improves accuracy)
#
#     Returns:
#         {
#             "source": "OCR_SCAN",
#             "ocr_text": str,
#             "ocr_confidence": float,
#             "extracted_urls": list[str],
#             "scanned_urls": list[dict],
#             "verdict": "PHISHING" | "SAFE",
#         }
#     """
#     import pytesseract
#     from PIL import Image, ImageEnhance
#
#     img = Image.open(image) if isinstance(image, str) else Image.open(io.BytesIO(image))
#     img = ImageEnhance.Contrast(img.convert("L")).enhance(2.0)
#     ocr_text = pytesseract.image_to_string(img)
#
#     urls = extract_urls(ocr_text)
#     results = [scan_url(u) for u in urls]
#     has_threat = any(r["verdict"] == "PHISHING" for r in results)
#
#     return {
#         "source": "OCR_SCAN",
#         "ocr_text": ocr_text,
#         "ocr_confidence": 0.0,  # TODO: parse from pytesseract OSD data
#         "extracted_urls": urls,
#         "scanned_urls": results,
#         "verdict": "PHISHING" if has_threat else "SAFE",
#     }


# ─────────────────────────────────────────────────────────────────────────────
# FUTURE — ML / API Hybrid Check (Layer 4+)
# ─────────────────────────────────────────────────────────────────────────────

# async def check_virustotal_api(url: str) -> dict:
#     """Query the VirusTotal URL scanning API for a reputation verdict.
#
#     This will be injected into the heuristic chain as a fallback when the
#     local rules engine returns SAFE but the URL is still suspicious (e.g.
#     newly registered domain, URL shortener, etc.).
#
#     Integration plan:
#       1. POST the URL to https://www.virustotal.com/api/v3/urls
#       2. Poll the analysis endpoint until completion.
#       3. Parse `data.attributes.last_analysis_stats` for malicious count.
#       4. If malicious > 0, override verdict to PHISHING with source=VT.
#
#     Requires:
#       - VIRUSTOTAL_API_KEY environment variable
#       - httpx or aiohttp for async HTTP
#       - Rate limiting (4 req/min on free tier)
#
#     Returns:
#         {
#             "url": url,
#             "vt_score": {"malicious": int, "suspicious": int, "clean": int},
#             "verdict": "PHISHING" | "SAFE",
#             "source": "VIRUSTOTAL"
#         }
#     """
#     import httpx
#     import os
#
#     api_key = os.environ["VIRUSTOTAL_API_KEY"]
#     async with httpx.AsyncClient() as client:
#         resp = await client.post(
#             "https://www.virustotal.com/api/v3/urls",
#             headers={"x-apikey": api_key},
#             data={"url": url},
#         )
#         analysis_id = resp.json()["data"]["id"]
#         # ... poll for result, parse stats, return verdict
#         pass
