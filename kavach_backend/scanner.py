# =============================================================================
# KAVACH — scanner.py (Threat Intelligence Engine v2.0)
# =============================================================================
#
# Multi-modal scanner for the KAVACH Pre-Click Interceptor.
#
# Pipelines:
#   Pipeline 1 — Text:  raw SMS text ──► extract_urls() ──► scan_url()
#   Pipeline 2 — Image: image bytes  ──► scan_image()   ──► decode QR
#                                                        ──► scan_url()
#   Pipeline 3 — OCR:   (stub) screenshot ──► OCR text ──► extract_urls()
#
# Verdict Flow (scan_url):
#   1. Redirect Trace       — expand URL shorteners to final destination
#   2. Dynamic Whitelist    — verified SBI domains → immediate SAFE
#   3. Heuristic Rules      — brand spoof, homoglyph, risky TLD
#   4. ML Typo Engine       — char TF-IDF + cosine similarity to core assets
#                             catches visual/phonetic typo-squatting
#   5. Threat Intelligence  — VirusTotal + Google Safe Browsing (3s timeout)
#                             catches entirely unknown zero-day domains
#   6. If no gate fires     → SAFE
#
# Verdict is STRICTLY BINARY: SAFE or BLOCKED.  No grey-zone verdicts.
# =============================================================================

from __future__ import annotations

import base64
import io
import logging
import os
import re
import socket
from urllib.parse import urlparse

import requests
# NOTE: whois import removed — WHOIS fallback eliminated per Red Team audit.
from PIL import Image
from pyzbar import pyzbar

from ml_typo_engine import TypoSimilarityEngine

logger = logging.getLogger("kavach.scanner")

# ─────────────────────────────────────────────────────────────────────────────
# CONFIGURATION — Whitelists, blacklists, and pattern tables
# ─────────────────────────────────────────────────────────────────────────────

# Official SBI domains that are SAFE and must never be flagged.
# This is the "Dynamic Whitelist" — add new verified marketing domains here
# as campaigns launch.  Any domain in this set bypasses all heuristic checks.
WHITELISTED_DOMAINS: set[str] = {
    # ── Core banking portals ──
    "onlinesbi.sbi",
    "sbiyono.sbi",
    "sbi.co.in",
    "bank.sbi",
    "www.onlinesbi.sbi",
    "www.sbiyono.sbi",
    "www.sbi.co.in",
    "www.bank.sbi",
    # ── Verified marketing / promotional domains ──
    "sbi-yono-offers.in",
    "www.sbi-yono-offers.in",
    "sbirewardz.sbi",
    "www.sbirewardz.sbi",
}

# ─────────────────────────────────────────────────────────────────────────────
# SCAN PIPELINE — Timeouts & Limits
# ─────────────────────────────────────────────────────────────────────────────

# Strict timeout for URL shortener / redirect expansion.  Redirect tracing is
# the first step in the pipeline and directly affects end-to-end latency.
_REDIRECT_TRACE_TIMEOUT: float = 3.0

# Strict timeout for external Threat Intelligence API calls (VirusTotal,
# Google Safe Browsing).  If the API is slow or down, we fail-open and
# fall back to local heuristic + ML typo-similarity verdicts.
_THREAT_API_TIMEOUT: float = 3.0

# Maximum number of redirect hops we will follow while expanding a shortened
# or obfuscated URL.  This prevents malicious infinite redirect loops from
# stalling or crashing the scanner.
_REDIRECT_MAX_HOPS: int = 5

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

# ── Core Assets for ML Typo Similarity ──
# These are the crown-jewel domains we protect.  Any incoming domain with
# >85% character n-gram cosine similarity is typo-squatting.
CORE_PROTECTED_ASSETS: list[str] = [
    "onlinesbi.sbi",
    "sbiyono.sbi",
    "statebankofindia.com",
    "bank.sbi",
    "sbi.co.in",
]

# ML similarity threshold.  0.85 = 85% char n-gram cosine similarity.
_TYPO_SIMILARITY_THRESHOLD: float = 0.85

_TYPO_ENGINE = TypoSimilarityEngine(
    CORE_PROTECTED_ASSETS,
    threshold=_TYPO_SIMILARITY_THRESHOLD,
)

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


def resolve_final_url(url: str) -> str:
    """Resolve a potentially shortened URL to its final destination.

    Fraudsters often hide phishing pages behind URL shorteners such as
    ``bit.ly``, ``tinyurl`` or ``t.co`` so the visible link looks harmless.
    This helper follows HTTP redirects and returns the final landing URL
    before the heuristic engine or WHOIS checks run.

    Performance and safety guards:
      - Uses a strict 3-second timeout to protect P95 latency
      - Limits redirect chains to 5 hops to prevent infinite loops
      - Uses HEAD first so we only fetch headers, not the full HTML body
      - Falls back to streamed GET for servers that do not support HEAD

    If resolution fails for any reason, the original URL is returned so the
    scanner still produces a verdict instead of crashing or dropping the scan.

    Args:
        url: The inbound URL from SMS text, QR payload, or OCR output.

    Returns:
        The final resolved URL if redirect tracing succeeds, otherwise the
        original input URL.
    """
    session = requests.Session()
    session.max_redirects = _REDIRECT_MAX_HOPS

    try:
        # HEAD is the fastest and cheapest way to expand short links because
        # we only need redirect headers, not the destination page body.
        response = session.head(
            url,
            allow_redirects=True,
            timeout=_REDIRECT_TRACE_TIMEOUT,
        )

        # Some redirectors reject HEAD even though GET would succeed.  We use
        # a streamed GET fallback so requests stops after headers and does not
        # download the actual HTML body.
        if response.status_code in {405, 501}:
            response.close()
            response = session.get(
                url,
                allow_redirects=True,
                timeout=_REDIRECT_TRACE_TIMEOUT,
                stream=True,
            )

        final_url = response.url or url
        redirect_hops = len(response.history)

        logger.info(
            "Redirect trace: %s -> %s (%d hop%s)",
            url,
            final_url,
            redirect_hops,
            "" if redirect_hops == 1 else "s",
        )
        response.close()
        return final_url

    except requests.exceptions.RequestException as exc:
        logger.warning(
            "Redirect trace failed for %s (%s: %s) -> scanning original URL",
            url,
            type(exc).__name__,
            exc,
        )
        return url

    finally:
        session.close()


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


# ─────────────────────────────────────────────────────────────────────────────
# GATE 3 — ML TYPO-SQUATTING DETECTION
# ─────────────────────────────────────────────────────────────────────────────


def check_ml_typo_similarity(domain: str) -> tuple[bool, str | None, float]:
    """Detect typo-squatting with char TF-IDF cosine similarity.

    The model compares character n-gram overlap against protected domains,
    catching sub-word typo variants without brittle edit-distance rules.

    Args:
        domain: The bare domain (no port, no scheme).

    Returns:
        (is_threat, reason_string_or_None, highest_similarity_score)
    """
    # Domains already in the whitelist are guaranteed safe
    if domain in WHITELISTED_DOMAINS:
        return False, None, 0.0

    typo_result = _TYPO_ENGINE.score(domain)

    if typo_result.is_match:
        closest_asset = typo_result.protected_domain
        reason = (
            f"TYPOSQUAT_DETECTED: '{domain}' is {typo_result.score:.0%} similar to "
            f"protected asset '{closest_asset}' — likely typo-squatting"
        )
        logger.warning(
            "ML typo match THREAT: %s <-> %s (score=%.3f, threshold=%.2f)",
            domain,
            typo_result.protected_domain,
            typo_result.score,
            _TYPO_SIMILARITY_THRESHOLD,
        )
        return True, reason, typo_result.score

    return False, None, typo_result.score


# ─────────────────────────────────────────────────────────────────────────────
# GATE 4 — THREAT INTELLIGENCE (VirusTotal + Google Safe Browsing)
# ─────────────────────────────────────────────────────────────────────────────


def _query_virustotal(url: str) -> bool:
    """Query VirusTotal URL reputation API.

    Uses the ``/api/v3/urls/{id}`` GET endpoint with base64url-encoded URL ID.
    Returns True if at least one engine flags the URL as malicious.

    Fails-open (returns False) on any error so the scanner stays alive.
    """
    api_key = os.environ.get("VIRUSTOTAL_API_KEY", "")
    if not api_key:
        logger.debug("VIRUSTOTAL_API_KEY not set — skipping VT check")
        return False

    try:
        # VirusTotal URL ID = base64url of the URL without padding
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": api_key},
            timeout=_THREAT_API_TIMEOUT,
        )

        if resp.status_code != 200:
            logger.debug(
                "VirusTotal returned HTTP %d for %s — treating as unknown",
                resp.status_code,
                url,
            )
            return False

        data = resp.json()
        stats = (
            data.get("data", {})
            .get("attributes", {})
            .get("last_analysis_stats", {})
        )
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)

        if malicious > 0 or suspicious > 0:
            logger.warning(
                "VirusTotal THREAT: %s — malicious=%d, suspicious=%d",
                url,
                malicious,
                suspicious,
            )
            return True

        return False

    except requests.exceptions.Timeout:
        logger.warning("VirusTotal timeout for %s after %ss — fail-open", url, _THREAT_API_TIMEOUT)
        return False
    except requests.exceptions.RequestException as exc:
        logger.warning("VirusTotal request failed for %s (%s) — fail-open", url, exc)
        return False
    except (KeyError, ValueError, TypeError) as exc:
        logger.warning("VirusTotal parse error for %s (%s) — fail-open", url, exc)
        return False
    except Exception as exc:
        logger.warning("VirusTotal unexpected error for %s (%s: %s) — fail-open", url, type(exc).__name__, exc)
        return False


def _query_google_safe_browsing(url: str) -> bool:
    """Query Google Safe Browsing Lookup API v4.

    Sends a ``threatMatches:find`` POST with the URL.  Returns True if
    Google identifies any threat match.

    Fails-open (returns False) on any error.
    """
    api_key = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY", "")
    if not api_key:
        logger.debug("GOOGLE_SAFE_BROWSING_API_KEY not set — skipping GSB check")
        return False

    try:
        payload = {
            "client": {
                "clientId": "kavach-scanner",
                "clientVersion": "2.0.0",
            },
            "threatInfo": {
                "threatTypes": [
                    "MALWARE",
                    "SOCIAL_ENGINEERING",
                    "UNWANTED_SOFTWARE",
                    "POTENTIALLY_HARMFUL_APPLICATION",
                ],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}],
            },
        }

        resp = requests.post(
            f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={api_key}",
            json=payload,
            timeout=_THREAT_API_TIMEOUT,
        )

        if resp.status_code != 200:
            logger.debug(
                "Google Safe Browsing returned HTTP %d for %s — treating as unknown",
                resp.status_code,
                url,
            )
            return False

        matches = resp.json().get("matches")
        if matches:
            logger.warning(
                "Google Safe Browsing THREAT: %s — %d match(es)",
                url,
                len(matches),
            )
            return True

        return False

    except requests.exceptions.Timeout:
        logger.warning("Google Safe Browsing timeout for %s after %ss — fail-open", url, _THREAT_API_TIMEOUT)
        return False
    except requests.exceptions.RequestException as exc:
        logger.warning("Google Safe Browsing request failed for %s (%s) — fail-open", url, exc)
        return False
    except (KeyError, ValueError, TypeError) as exc:
        logger.warning("Google Safe Browsing parse error for %s (%s) — fail-open", url, exc)
        return False
    except Exception as exc:
        logger.warning("Google Safe Browsing unexpected error for %s (%s: %s) — fail-open", url, type(exc).__name__, exc)
        return False


def query_threat_intelligence(url: str) -> tuple[bool, str | None]:
    """Query the Hive Mind — VirusTotal + Google Safe Browsing.

    Runs both APIs sequentially (each with a strict 3s timeout).
    If EITHER flags the URL as malicious, returns (True, reason).
    If both time out or fail, returns (False, None) — fail-open
    to let the local heuristic + ML typo-similarity gate handle it.

    Args:
        url: The full URL to check.

    Returns:
        (is_threat, reason_string_or_None)
    """
    sources: list[str] = []

    if _query_virustotal(url):
        sources.append("VIRUSTOTAL")

    if _query_google_safe_browsing(url):
        sources.append("GOOGLE_SAFE_BROWSING")

    if sources:
        reason = f"THREAT_INTEL: flagged by {' + '.join(sources)}"
        logger.warning("Threat Intelligence BLOCKED %s — %s", url, reason)
        return True, reason

    return False, None


# NOTE: _whois_verify_bank_ownership() REMOVED per Red Team audit.
# The scanning pipeline is now strictly binary (SAFE / BLOCKED).
# WHOIS-based verdict downgrading created dangerous user ambiguity.
# New legitimate marketing domains must be added to WHITELISTED_DOMAINS.


def scan_url(url: str) -> dict:
    """Run a URL through the full scan pipeline.

    Pipeline:
      1. **Redirect Trace** — expand URL shorteners / obfuscated links to the
         final destination URL before any security decisions are made.
      2. Parse and extract domain from the resolved destination.
      3. **Dynamic Whitelist** — if the domain is in ``WHITELISTED_DOMAINS``,
         return SAFE immediately (zero heuristic overhead).
      4. **Heuristic Rules Engine** — run brand-spoofing, homoglyph, and
         risky-TLD checks.
      5. **ML Typo Similarity** — char TF-IDF typo-squatting detection.
      6. **Threat Intelligence APIs** — VirusTotal + Google Safe Browsing.
      7. If no gate fires → SAFE.  Otherwise → BLOCKED.

    Verdict is STRICTLY BINARY: ``SAFE`` or ``BLOCKED``.
    No grey-zone or advisory verdicts.

    Args:
        url: A single HTTP/HTTPS URL string.

    Returns:
        A dict with keys:
          - url:     the original inbound URL
          - resolved_url: the final URL after redirect expansion
          - domain:  the extracted domain (netloc)
          - verdict: ``"SAFE"`` | ``"BLOCKED"``
          - rule:    human-readable reason (for BLOCKED verdicts)
    """
    resolved_url = resolve_final_url(url)
    parsed = urlparse(resolved_url)
    domain = parsed.netloc.lower().strip()
    if not domain:
        return {
            "url": url,
            "resolved_url": resolved_url,
            "domain": "",
            "verdict": "BLOCKED",
            "rule": "MALFORMED_URL: unable to extract domain",
        }

    # Strip port number if present (e.g. evil.xyz:8080 → evil.xyz)
    domain_no_port = domain.split(":")[0]

    # ── GATE 1: Dynamic Whitelist ─────────────────────────────────────────
    # If the domain is pre-verified, skip ALL heuristic checks.
    if domain_no_port in WHITELISTED_DOMAINS:
        logger.info(
            "WHITELIST HIT: %s is a verified official domain → SAFE",
            domain_no_port,
        )
        return {
            "url": url,
            "resolved_url": resolved_url,
            "domain": domain_no_port,
            "verdict": "SAFE",
            "alert": "Verified Official Domain.",
        }

    # ── GATE 2: Heuristic Rules Engine ────────────────────────────────────
    # Run each rule in order — short-circuit on first hit.
    heuristic_reason: str | None = None
    for rule_fn in _HEURISTIC_CHAIN:
        reason = rule_fn(domain_no_port)
        if reason is not None:
            heuristic_reason = reason
            break

    # ── GATE 3: ML Typo Similarity ───────────────────────────────────────
    # Character n-gram TF-IDF catches visual/phonetic typo variants without
    # relying on brittle edit-distance or exact hardcoded patterns.
    if heuristic_reason is None:
        is_typo_threat, typo_reason, _typo_score = check_ml_typo_similarity(
            domain_no_port
        )
        if is_typo_threat:
            heuristic_reason = typo_reason

    # ── GATE 4: Threat Intelligence APIs ──────────────────────────────────
    # Query VirusTotal + Google Safe Browsing for entirely unknown zero-day
    # domains that don't match any local heuristic or ML typo pattern.
    # Only called if no local gate has already flagged the URL.
    if heuristic_reason is None:
        is_api_threat, api_reason = query_threat_intelligence(resolved_url)
        if is_api_threat:
            # API-confirmed malicious — immediate BLOCKED.
            logger.warning(
                "Threat Intelligence BLOCKED %s: %s", domain_no_port, api_reason
            )
            return {
                "url": url,
                "resolved_url": resolved_url,
                "domain": domain_no_port,
                "verdict": "BLOCKED",
                "rule": api_reason,
            }

    # If no gate fired at all, the URL is clean.
    if heuristic_reason is None:
        return {
            "url": url,
            "resolved_url": resolved_url,
            "domain": domain_no_port,
            "verdict": "SAFE",
        }

    # ── BLOCKED: Heuristic/ML typo gate fired — binary block ──────────
    # No WHOIS downgrade.  Any URL not in the whitelist that triggers a
    # heuristic or ML typo rule is definitively BLOCKED.
    logger.warning(
        "BLOCKED %s — rule: %s (binary verdict, no WHOIS override)",
        domain_no_port,
        heuristic_reason,
    )
    return {
        "url": url,
        "resolved_url": resolved_url,
        "domain": domain_no_port,
        "verdict": "BLOCKED",
        "rule": heuristic_reason,
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
