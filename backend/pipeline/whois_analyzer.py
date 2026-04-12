"""
pipeline/whois_analyzer.py — Level 2: WHOIS Domain Age Analysis

Why domain age matters:
  Phishing infrastructure has a very short lifespan by design.
  Attackers register domains, run a campaign for days/weeks, then
  abandon them. Over 90% of phishing URLs use domains < 30 days old.

  A domain registered yesterday impersonating your bank is extremely
  high-risk, even if it has no explicit threat-intel record yet.

Implementation note on blocking:
  python-whois performs synchronous socket I/O. Running it directly
  in an async handler would block the entire event loop.
  We delegate it to a thread-pool executor (`run_in_executor`) so the
  FastAPI event loop stays free to handle other requests concurrently.
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Optional

import whois
import tldextract

from config import settings
from models import WhoisResult

logger = logging.getLogger(__name__)


def _fetch_whois(domain: str) -> whois.WhoisEntry:
    """Synchronous WHOIS fetch — runs in a thread pool."""
    return whois.whois(domain)


def _parse_creation_date(raw) -> Optional[datetime]:
    """
    python-whois sometimes returns a list (when multiple dates appear
    in the WHOIS record).  We take the earliest one as the true
    registration date.
    """
    if raw is None:
        return None
    if isinstance(raw, list):
        raw = min(raw)  # earliest date = actual creation
    if not isinstance(raw, datetime):
        return None
    # Make timezone-aware if naive (WHOIS dates are almost always UTC)
    if raw.tzinfo is None:
        raw = raw.replace(tzinfo=timezone.utc)
    return raw


async def check_domain_age(url: str) -> WhoisResult:
    """
    Asynchronously retrieves WHOIS information for the hostname in `url`
    and returns the domain age in days.

    Graceful degradation:
      - WHOIS timeout    → WhoisResult(checked=False, error=...)
      - No creation date → WhoisResult(checked=True, age_days=None)
      - Any exception    → WhoisResult(checked=False, error=str(exc))

    In all failure cases the pipeline continues; we simply don't apply
    the age-based risk factor.
    """
    # Extract bare domain ("pay.evil.com" → "evil.com")
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}"

    if not extracted.domain or not extracted.suffix:
        return WhoisResult(checked=False, error="Could not extract domain from URL")

    try:
        loop = asyncio.get_running_loop()
        # Run blocking WHOIS call in a thread pool with timeout
        w: whois.WhoisEntry = await asyncio.wait_for(
            loop.run_in_executor(None, _fetch_whois, domain),
            timeout=settings.WHOIS_TIMEOUT,
        )
    except asyncio.TimeoutError:
        logger.warning("WHOIS timeout for domain: %s", domain)
        return WhoisResult(
            checked=False,
            error=f"WHOIS server did not respond within {settings.WHOIS_TIMEOUT}s",
        )
    except Exception as exc:
        logger.error("WHOIS error for %s: %s", domain, exc)
        return WhoisResult(checked=False, error=str(exc))

    creation_date = _parse_creation_date(getattr(w, "creation_date", None))
    if creation_date is None:
        # Some ccTLDs don't expose creation date in WHOIS
        return WhoisResult(checked=True, age_days=None, error="Creation date not available")

    now = datetime.now(timezone.utc)
    age_days = (now - creation_date).days

    registrar: Optional[str] = getattr(w, "registrar", None)
    if isinstance(registrar, list):
        registrar = registrar[0]

    logger.info("Domain %s: age=%d days, registrar=%s", domain, age_days, registrar)

    return WhoisResult(
        checked=True,
        age_days=age_days,
        creation_date=creation_date.isoformat(),
        registrar=str(registrar) if registrar else None,
    )
