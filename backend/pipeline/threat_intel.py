"""
pipeline/threat_intel.py — Level 1: External Threat Intelligence

Queries the Google Safe Browsing Lookup API v4.
Documentation: https://developers.google.com/safe-browsing/v4/lookup-api

Why GSB first?
  Google maintains a live database of ~5 billion known-bad URLs.
  A positive match here is the highest-confidence signal in the pipeline —
  far more reliable than any heuristic. We run it first so that if the
  network is slow we can still return partial results from local stages.

Getting a free API key:
  1. Go to https://console.cloud.google.com/
  2. Create or select a project
  3. Enable "Safe Browsing API"
  4. Navigate to APIs & Services → Credentials → Create API Key
  5. Set GOOGLE_SAFE_BROWSING_KEY=<key> in your .env file

Free quota: 10 000 requests / day, no billing required.
"""

import logging
from typing import Optional

import httpx

from config import settings
from models import ThreatIntelResult

logger = logging.getLogger(__name__)

# All threat categories we care about
_THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",        # phishing
    "UNWANTED_SOFTWARE",
    "POTENTIALLY_HARMFUL_APPLICATION",
]

_GSB_ENDPOINT = (
    "https://safebrowsing.googleapis.com/v4/threatMatches:find"
)


async def check_google_safe_browsing(url: str) -> ThreatIntelResult:
    """
    Asynchronously queries Google Safe Browsing for the given URL.

    Returns ThreatIntelResult with is_threat=True and a list of
    matched threat categories if the URL appears in Google's database.

    If the API key is absent or the request fails, returns a graceful
    empty result (checked=False) so the rest of the pipeline continues.
    """
    api_key = settings.GOOGLE_SAFE_BROWSING_KEY
    if not api_key:
        logger.debug("GSB API key not configured — skipping threat intel check.")
        return ThreatIntelResult(checked=False, error="API key not configured")

    payload = {
        "client": {
            "clientId":      "phishguard",
            "clientVersion": settings.APP_VERSION,
        },
        "threatInfo": {
            "threatTypes":      _THREAT_TYPES,
            "platformTypes":    ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries":    [{"url": url}],
        },
    }

    try:
        async with httpx.AsyncClient(timeout=settings.GSB_TIMEOUT) as client:
            resp = await client.post(
                _GSB_ENDPOINT,
                params={"key": api_key},
                json=payload,
            )
            resp.raise_for_status()

        data = resp.json()
        matches = data.get("matches", [])

        if not matches:
            # Empty response body means URL is clean per Google's database
            return ThreatIntelResult(checked=True, is_threat=False)

        threat_types = [m.get("threatType", "UNKNOWN") for m in matches]
        logger.warning("GSB hit for %s: %s", url, threat_types)
        return ThreatIntelResult(
            checked=True,
            is_threat=True,
            threat_types=threat_types,
        )

    except httpx.HTTPStatusError as exc:
        # 4xx usually means bad API key; log but don't crash
        logger.error("GSB HTTP error %s: %s", exc.response.status_code, exc)
        return ThreatIntelResult(
            checked=False,
            error=f"HTTP {exc.response.status_code}: {exc.response.text[:200]}",
        )
    except Exception as exc:
        logger.error("GSB unexpected error: %s", exc)
        return ThreatIntelResult(checked=False, error=str(exc))
