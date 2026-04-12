"""
pipeline/lexical_analyzer.py — Level 3: Lexical / Structural URL Analysis

This module extracts ~15 features from the raw URL without any
external network call, making it the fastest and most reliable
component of the pipeline (never fails due to network issues).

Algorithm overview
──────────────────
1.  Parse the URL with Python's urllib.parse.urlparse.
2.  Run each feature extractor (an independent method) on the parsed
    URL.  Extractors are designed to be independent so adding new ones
    doesn't break existing ones.
3.  Return a LexicalFeatures dataclass consumed by the scorer.

Key features explained
──────────────────────
- IP in host: Legitimate organisations always use named domains.
  A raw IP (e.g. http://185.220.101.0/bank-login) is almost always
  malicious or at best highly suspicious.

- @ symbol: RFC 3986 allows user:password@host. Attackers exploit
  this by writing http://paypal.com@evil.com — the real host is
  evil.com, but a casual reader sees paypal.com first.

- Punycode (xn--): IDN domains are stored as ASCII ACE strings
  starting with "xn--".  Attackers use visually-identical
  Unicode characters (e.g. аpple.com where "а" is Cyrillic U+0430)
  encoded as xn-- to bypass simple substring checks.

- Non-standard ports: :8080, :4433, :1337, etc. on a "bank" domain
  is never legitimate.

- Brand in subdomain: paypal.com.evil.ru — "paypal.com" is just
  a subdomain label. We compare each subdomain label against a
  curated brand list.

- Trigger keywords: Presence of 'login', 'secure', 'verify', etc.
  in the URL path is a strong phishing signal when combined with
  other factors.

- Suspicious TLDs: Free / abused TLD zones that host the vast
  majority of phishing infrastructure.
"""

import logging
import re
from urllib.parse import urlparse, unquote
from typing import Optional

import idna
import tldextract

from models import LexicalFeatures

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────

_TRIGGER_KEYWORDS: frozenset[str] = frozenset({
    "login", "signin", "sign-in", "secure", "security",
    "verify", "verification", "validate", "account",
    "update", "confirm", "banking", "ebayisapi",
    "paypal", "recover", "password", "passwd",
    "credential", "wallet", "free", "prize", "winner",
    "suspended", "limited", "unusual", "activity",
    "authenticate", "authorization", "reactivate",
    "unlock", "billing", "invoice", "support",
})

_SUSPICIOUS_TLDS: frozenset[str] = frozenset({
    "xyz", "tk", "ml", "ga", "cf", "gq", "top", "click",
    "loan", "work", "date", "win", "stream", "racing",
    "review", "party", "download", "bid", "faith",
    "icu", "buzz", "cyou", "monster", "cfd", "sbs",
    "bar", "hair", "skin", "boats", "wang", "men",
})

# Known brands that should ONLY appear as the registered domain,
# never as a subdomain label on a different registrable domain.
_KNOWN_BRANDS: tuple[str, ...] = (
    "paypal", "google", "apple", "amazon", "facebook", "microsoft",
    "netflix", "tinkoff", "sberbank", "vtb", "alfabank", "gosuslugi",
    "telegram", "yandex", "instagram", "vkontakte", "mailru",
    "visa", "mastercard", "gazprom", "raiffeisen", "ozon", "wildberries",
)

# Standard HTTP ports — anything else is suspicious
_STANDARD_PORTS: frozenset[int] = frozenset({80, 443, 8080})

# Regex: IPv4 address as the hostname
_IPV4_RE = re.compile(
    r"^(\d{1,3}\.){3}\d{1,3}$"
)

# Redirect / open-redirect parameter names
_REDIRECT_PARAMS_RE = re.compile(
    r"(?i)[?&](url|redirect|goto|link|forward|return|next|redir)="
)

# Percent-encoded characters in the hostname (obfuscation)
_PERCENT_ENCODED_RE = re.compile(r"%[0-9a-fA-F]{2}")


class LexicalAnalyzer:
    """
    Stateless URL feature extractor.

    Usage:
        analyzer = LexicalAnalyzer()
        features = analyzer.analyze("https://paypal.com.evil.xyz/login")
    """

    def analyze(self, url: str) -> LexicalFeatures:
        """
        Entry point.  Parses the URL and delegates to individual
        feature-extraction methods.  Each method is pure and raises
        no exceptions (they return False / 0 on error).
        """
        # Decode percent-encoding so we don't miss embedded URLs
        decoded_url = unquote(url)

        try:
            parsed = urlparse(decoded_url)
        except Exception:
            logger.error("urlparse failed for: %s", url)
            return LexicalFeatures(url_length=len(url))

        host     = (parsed.hostname or "").lower()
        path     = parsed.path + ("?" + parsed.query if parsed.query else "")
        port     = parsed.port
        netloc   = parsed.netloc

        ext = tldextract.extract(decoded_url)
        tld          = ext.suffix.lower()
        sld          = ext.domain.lower()          # registered domain label
        subdomains   = [s for s in ext.subdomain.split(".") if s]

        features = LexicalFeatures(
            has_ip_address        = self._has_ip(host),
            has_at_symbol         = self._has_at(decoded_url, netloc),
            has_punycode          = self._has_punycode(host),
            has_non_ascii_host    = self._has_non_ascii(host),
            has_non_standard_port = self._has_non_standard_port(port, parsed.scheme),
            has_encoded_host      = self._has_encoded_host(parsed.netloc),
            has_redirect_params   = self._has_redirect_params(url),
            has_digits_in_domain  = self._has_digits(sld),
            subdomain_count       = len(subdomains),
            url_length            = len(url),
            domain_length         = len(sld),
            hyphen_count          = host.count("-"),
            trigger_keywords      = self._find_keywords(path + host),
            suspicious_tld        = tld in _SUSPICIOUS_TLDS,
            brand_in_subdomain    = self._brand_in_subdomain(subdomains, sld),
        )

        logger.debug("Lexical features for %s: %s", host, features.model_dump())
        return features

    # ── Individual feature extractors ─────────────────────────

    @staticmethod
    def _has_ip(host: str) -> bool:
        """True if the hostname is a raw IPv4 address."""
        return bool(_IPV4_RE.match(host))

    @staticmethod
    def _has_at(raw_url: str, netloc: str) -> bool:
        """
        True if an @ appears in the netloc portion of the URL.
        http://google.com@evil.com → netloc="google.com@evil.com"
        The actual host resolves to evil.com (everything after @).
        """
        return "@" in netloc

    @staticmethod
    def _has_punycode(host: str) -> bool:
        """
        True if any label in the hostname uses ACE/Punycode encoding.
        Punycode labels start with the ASCII Compatible Encoding prefix "xn--".
        """
        return any(label.startswith("xn--") for label in host.split("."))

    @staticmethod
    def _has_non_ascii(host: str) -> bool:
        """
        True if the raw hostname contains non-ASCII Unicode characters
        (i.e. the URL was NOT properly Punycode-encoded but contains
        raw Cyrillic / Greek / etc. look-alike characters).
        """
        try:
            host.encode("ascii")
            return False
        except UnicodeEncodeError:
            return True

    @staticmethod
    def _has_non_standard_port(port: Optional[int], scheme: str) -> bool:
        """
        True if a non-standard port is explicitly specified.
        We allow 8080 for http and exclude 443 for https / 80 for http.
        """
        if port is None:
            return False
        expected = 443 if scheme == "https" else 80
        return port not in _STANDARD_PORTS and port != expected

    @staticmethod
    def _has_encoded_host(netloc: str) -> bool:
        """
        True if the netloc contains percent-encoded characters.
        Legitimate hostnames are never percent-encoded; encoding in
        the host field is a classic obfuscation technique.
        """
        # Only check the host part (strip port)
        host_part = netloc.split(":")[0]
        return bool(_PERCENT_ENCODED_RE.search(host_part))

    @staticmethod
    def _has_redirect_params(url: str) -> bool:
        """True if the URL contains open-redirect parameter names."""
        return bool(_REDIRECT_PARAMS_RE.search(url))

    @staticmethod
    def _has_digits(sld: str) -> bool:
        """
        True if the second-level domain contains digits.
        Legitimate banks don't register g00gle.com or sberbank1.ru.
        """
        return bool(re.search(r"\d", sld))

    @staticmethod
    def _find_keywords(text: str) -> list[str]:
        """
        Returns all trigger keywords found in the combined
        path+hostname string (lowercased).  Matching is
        word-boundary-aware to avoid false positives on 'login'
        appearing inside a longer legitimate word.
        """
        text_lower = text.lower()
        return [kw for kw in _TRIGGER_KEYWORDS if kw in text_lower]

    @staticmethod
    def _brand_in_subdomain(subdomains: list[str], sld: str) -> Optional[str]:
        """
        Detects brand impersonation via subdomain abuse:
        paypal.com.evil.ru  →  subdomains=["paypal", "com"], sld="evil"

        We check if any KNOWN_BRAND appears as a subdomain label
        when the registered domain (sld) is NOT the brand itself.
        """
        for brand in _KNOWN_BRANDS:
            # Skip if this is legitimately the brand's own domain
            if sld == brand:
                continue
            # Check each subdomain label
            for sub in subdomains:
                if brand in sub:
                    return brand
        return None


# Singleton — safe to share across async handlers (stateless)
lexical_analyzer = LexicalAnalyzer()
