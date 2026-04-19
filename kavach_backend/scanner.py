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
#   4. Fuzzy String Match   — SequenceMatcher >80% similarity to core assets
#                             catches dynamic typo-squatting without hardcoding
#   5. Threat Intelligence  — VirusTotal + Google Safe Browsing (3s timeout)
#                             catches entirely unknown zero-day domains
#   6. WHOIS Fallback       — if flagged, verify registrant before blocking
#   7. If no gate fires     → SAFE
# =============================================================================

from __future__ import annotations

import base64
import io
import logging
import os
import re
import socket
from difflib import SequenceMatcher
from urllib.parse import urlparse

import requests
import whois
from PIL import Image
from pyzbar import pyzbar

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
# WHOIS FALLBACK VERIFICATION — Configuration
# ─────────────────────────────────────────────────────────────────────────────

# Strict timeout for WHOIS lookups (seconds).  If the global registry is slow
# or unreachable, we fail-secure by defaulting to BLOCKED.
_WHOIS_TIMEOUT: float = 5.0

# Strict timeout for URL shortener / redirect expansion.  We keep this even
# tighter than WHOIS because redirect tracing is now the first step in the
# pipeline and directly affects end-to-end latency.
_REDIRECT_TRACE_TIMEOUT: float = 3.0

# Strict timeout for external Threat Intelligence API calls (VirusTotal,
# Google Safe Browsing).  If the API is slow or down, we fail-open and
# fall back to local heuristic + fuzzy matching verdicts.
_THREAT_API_TIMEOUT: float = 3.0

# Maximum number of redirect hops we will follow while expanding a shortened
# or obfuscated URL.  This prevents malicious infinite redirect loops from
# stalling or crashing the scanner.
_REDIRECT_MAX_HOPS: int = 5

# Case-insensitive strings that identify a domain as genuinely owned by SBI.
# If ANY of these appear in the WHOIS registrant org, name, or email fields,
# the heuristic PHISHING verdict is downgraded to GREY_ALERT.
WHOIS_BANK_IDENTIFIERS: list[str] = [
    "state bank of india",
    "sbi",
    "sbicaps",
    "sbi capital markets",
    "sbi funds management",
    "sbi cards",
]

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

# ── Core Assets for Fuzzy Matching ──
# These are the crown-jewel domains we protect.  Any incoming domain with
# >80% similarity (but NOT an exact whitelist match) is typo-squatting.
CORE_PROTECTED_ASSETS: list[str] = [
    "onlinesbi.sbi",
    "sbiyono.sbi",
    "statebankofindia.com",
    "bank.sbi",
    "sbi.co.in",
]

# Fuzzy similarity threshold.  0.80 = 80% character-sequence match.
# Tuned to catch "onlinesb1.sbi" (0.92), "sbiy0no.sbi" (0.86), etc.
# while ignoring unrelated domains like "example.com" (0.15).
_FUZZY_THRESHOLD: float = 0.80

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
# GATE 3 — FUZZY STRING MATCHING (Mathematical Typo-Squatting Detection)
# ─────────────────────────────────────────────────────────────────────────────


def check_fuzzy_similarity(domain: str) -> tuple[bool, str | None, float]:
    """Detect typo-squatting via mathematical string similarity.

    Uses ``difflib.SequenceMatcher`` to compare the incoming domain against
    each core protected asset.  If the similarity ratio exceeds the threshold
    but the domain is NOT an exact whitelist match, it's a typo-squat.

    This replaces the brittle hardcoded homoglyph list with a dynamic
    approach that catches zero-day typo variants automatically.

    Args:
        domain: The bare domain (no port, no scheme).

    Returns:
        (is_threat, reason_string_or_None, highest_similarity_ratio)
    """
    # Domains already in the whitelist are guaranteed safe
    if domain in WHITELISTED_DOMAINS:
        return False, None, 0.0

    highest_ratio = 0.0
    closest_asset = ""

    for asset in CORE_PROTECTED_ASSETS:
        ratio = SequenceMatcher(None, domain, asset).ratio()
        if ratio > highest_ratio:
            highest_ratio = ratio
            closest_asset = asset

    if highest_ratio > _FUZZY_THRESHOLD:
        reason = (
            f"FUZZY_TYPOSQUAT: '{domain}' is {highest_ratio:.0%} similar to "
            f"protected asset '{closest_asset}' — likely typo-squatting"
        )
        logger.warning(
            "Fuzzy match THREAT: %s ↔ %s (ratio=%.3f, threshold=%.2f)",
            domain,
            closest_asset,
            highest_ratio,
            _FUZZY_THRESHOLD,
        )
        return True, reason, highest_ratio

    return False, None, highest_ratio


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
    to let the local heuristic + fuzzy matching handle it.

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


def _whois_verify_bank_ownership(domain: str) -> dict | None:
    """WHOIS Fallback Verification — check if a flagged domain is owned by SBI.

    Called ONLY when the heuristic engine has flagged a URL as PHISHING.
    Performs a live WHOIS lookup to inspect the registrant's organization,
    name, and email fields.  If any field matches a known SBI identifier,
    the domain is likely a legitimate corporate registration that triggered
    a false positive (e.g. a new marketing campaign domain).

    Fail-secure design:
      - Strict ``_WHOIS_TIMEOUT`` second socket timeout
      - Any exception (network, parse, timeout) → returns None → stays BLOCKED

    Args:
        domain: The bare domain name to look up.

    Returns:
        A dict with WHOIS evidence if the domain IS owned by the bank,
        or ``None`` if it is NOT (or if the lookup fails).
    """
    original_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(_WHOIS_TIMEOUT)
        w = whois.whois(domain)

        # Collect all registrant-identifying strings for matching.
        # WHOIS data is notoriously inconsistent — fields may be str,
        # list[str], or None depending on the registrar.
        candidate_fields: list[str] = []

        for attr in ("org", "name", "emails", "registrant_name"):
            val = getattr(w, attr, None)
            if val is None:
                continue
            if isinstance(val, str):
                candidate_fields.append(val)
            elif isinstance(val, list):
                candidate_fields.extend(str(v) for v in val)

        # Case-insensitive match against known bank identifiers
        lowered = " | ".join(candidate_fields).lower()
        for identifier in WHOIS_BANK_IDENTIFIERS:
            if identifier in lowered:
                logger.info(
                    "WHOIS FALLBACK: %s matched bank identifier '%s' "
                    "in registrant data → downgrading to GREY_ALERT",
                    domain,
                    identifier,
                )
                return {
                    "matched_identifier": identifier,
                    "registrar": getattr(w, "registrar", "UNKNOWN"),
                    "org": getattr(w, "org", "UNKNOWN"),
                    "registrant_name": getattr(w, "name", "REDACTED"),
                }

        # WHOIS succeeded but registrant does NOT match the bank
        logger.info(
            "WHOIS FALLBACK: %s registrant does NOT match SBI — "
            "verdict stays PHISHING (org=%s, name=%s)",
            domain,
            getattr(w, "org", None),
            getattr(w, "name", None),
        )
        return None

    except whois.parser.PywhoisError as exc:
        # Domain not found in WHOIS, or WHOIS server refused
        logger.warning(
            "WHOIS FALLBACK: lookup failed for %s (PywhoisError: %s) "
            "→ fail-secure as PHISHING",
            domain,
            exc,
        )
        return None

    except socket.timeout:
        logger.warning(
            "WHOIS FALLBACK: lookup timed out for %s after %ss "
            "→ fail-secure as PHISHING",
            domain,
            _WHOIS_TIMEOUT,
        )
        return None

    except Exception as exc:
        # Catch-all: corrupt WHOIS response, network error, etc.
        logger.warning(
            "WHOIS FALLBACK: unexpected error for %s (%s: %s) "
            "→ fail-secure as PHISHING",
            domain,
            type(exc).__name__,
            exc,
        )
        return None

    finally:
        socket.setdefaulttimeout(original_timeout)


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
      5. **WHOIS Fallback Verification** — if heuristics flag PHISHING,
         perform a live WHOIS lookup to check if the registrant is actually
         SBI.  If confirmed → downgrade to GREY_ALERT.
      6. If WHOIS doesn't confirm bank ownership (or fails/times out) →
         fail-secure as PHISHING.

    Args:
        url: A single HTTP/HTTPS URL string.

    Returns:
        A dict with keys:
          - url:     the original inbound URL
          - resolved_url: the final URL after redirect expansion
          - domain:  the extracted domain (netloc)
          - verdict: ``"SAFE"`` | ``"GREY_ALERT"`` | ``"PHISHING"``
          - rule:    human-readable reason (for PHISHING / GREY_ALERT)
          - alert:   human-readable alert message (when applicable)
          - whois_evidence: dict (only present on GREY_ALERT downgrade)
    """
    resolved_url = resolve_final_url(url)
    parsed = urlparse(resolved_url)
    domain = parsed.netloc.lower().strip()
    if not domain:
        return {
            "url": url,
            "resolved_url": resolved_url,
            "domain": "",
            "verdict": "PHISHING",
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

    # ── GATE 3: Fuzzy String Matching ─────────────────────────────────────
    # Mathematical typo-squatting detection — catches zero-day typo variants
    # without requiring hardcoded pattern updates.
    if heuristic_reason is None:
        is_fuzzy_threat, fuzzy_reason, fuzzy_ratio = check_fuzzy_similarity(
            domain_no_port
        )
        if is_fuzzy_threat:
            heuristic_reason = fuzzy_reason

    # ── GATE 4: Threat Intelligence APIs ──────────────────────────────────
    # Query VirusTotal + Google Safe Browsing for entirely unknown zero-day
    # domains that don't match any local heuristic or fuzzy pattern.
    # Only called if no local gate has already flagged the URL.
    if heuristic_reason is None:
        is_api_threat, api_reason = query_threat_intelligence(resolved_url)
        if is_api_threat:
            # API-flagged threats bypass WHOIS downgrade — they are confirmed
            # malicious by global threat databases, not just heuristic guesses.
            logger.warning(
                "Threat Intelligence BLOCKED %s: %s", domain_no_port, api_reason
            )
            return {
                "url": url,
                "resolved_url": resolved_url,
                "domain": domain_no_port,
                "verdict": "PHISHING",
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

    # ── GATE 5: WHOIS Fallback Verification ───────────────────────────────
    # The heuristic/fuzzy engine flagged this URL.  Before blocking it,
    # perform a live WHOIS lookup to check if the registrant is actually
    # the bank. This prevents false positives on new SBI marketing domains.
    logger.info(
        "Heuristic/Fuzzy PHISHING flag for %s (rule: %s) — running WHOIS "
        "fallback verification...",
        domain_no_port,
        heuristic_reason,
    )

    whois_evidence = _whois_verify_bank_ownership(domain_no_port)

    if whois_evidence is not None:
        # ── GREY_ALERT: Downgraded verdict ────────────────────────────
        # The domain IS registered to SBI, but it's not in our whitelist
        # yet (likely a new campaign).  Warn the user without blocking.
        return {
            "url": url,
            "resolved_url": resolved_url,
            "domain": domain_no_port,
            "verdict": "GREY_ALERT",
            "rule": (
                f"WHOIS_DOWNGRADE: heuristic rule [{heuristic_reason}] "
                f"overridden — WHOIS registrant matches "
                f"'{whois_evidence['matched_identifier']}'"
            ),
            "alert": (
                "\u26a0\ufe0f KAVACH Notice: This is a new, unverified SBI "
                "promotional link. We recommend claiming offers directly "
                "inside your YONO app to stay completely safe."
            ),
            "whois_evidence": whois_evidence,
        }

    # ── BLOCKED: WHOIS did not confirm bank ownership ─────────────────
    # Fail-secure — maintain the original PHISHING verdict.
    return {
        "url": url,
        "resolved_url": resolved_url,
        "domain": domain_no_port,
        "verdict": "PHISHING",
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



