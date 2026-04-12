"""
config.py — Centralized configuration for PhishGuard backend.

All thresholds, weights and API keys live here so tuning
the model never requires touching business logic.
"""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # ── API Keys ─────────────────────────────────────────────
    # Get a free key at https://console.cloud.google.com/
    # Enable "Safe Browsing API" → create credentials → API key
    GOOGLE_SAFE_BROWSING_KEY: str = ""

    # ── Service metadata ──────────────────────────────────────
    APP_NAME: str = "PhishGuard Backend"
    APP_VERSION: str = "1.0.0"

    # ── Risk thresholds ───────────────────────────────────────
    # Score >= PHISHING_THRESHOLD → is_phishing = True
    PHISHING_THRESHOLD: int = 60
    # Score in [SUSPICIOUS_MIN, PHISHING_THRESHOLD) → uncertain
    SUSPICIOUS_MIN: int = 30

    # ── WHOIS age thresholds (days) ───────────────────────────
    DOMAIN_AGE_VERY_NEW: int = 7       # +50 pts  — almost always malicious
    DOMAIN_AGE_NEW: int = 30           # +35 pts  — 90 % of phishing domains
    DOMAIN_AGE_RECENT: int = 90        # +15 pts  — still elevated risk

    # ── URL structural limits ─────────────────────────────────
    MAX_SUBDOMAINS: int = 3            # paypal.com.evil.ru = 4 → flagged
    MAX_URL_LENGTH: int = 100          # characters
    MAX_DOMAIN_LENGTH: int = 35        # SLD character count
    MAX_HYPHENS: int = 3               # consecutive hyphens in hostname

    # ── HTTP client timeouts (seconds) ───────────────────────
    WHOIS_TIMEOUT: int = 10
    GSB_TIMEOUT: float = 5.0

    # ────────────────────────────────────────────────────────
    # Risk score weights
    # Each key maps to a Trigger constant (see pipeline/scorer.py)
    # Values represent the raw points added to risk_score (0–100 cap)
    # ────────────────────────────────────────────────────────
    WEIGHTS: dict = {
        # External intelligence — highest confidence
        "google_safe_browsing": 90,   # direct threat match from Google

        # WHOIS domain age
        "domain_very_new":      50,   # < 7 days
        "domain_new":           35,   # < 30 days
        "domain_recent":        15,   # < 90 days

        # URL structure
        "ip_in_url":            40,   # direct IP instead of hostname
        "at_symbol":            50,   # http://real@evil.com trick
        "punycode":             45,   # xn-- IDN homograph
        "non_ascii_host":       55,   # raw unicode in hostname
        "non_standard_port":    25,   # :8080, :4433, etc.
        "excessive_subdomains": 20,   # > MAX_SUBDOMAINS
        "long_url":             15,   # > MAX_URL_LENGTH chars
        "long_domain":          15,   # SLD > MAX_DOMAIN_LENGTH chars
        "excessive_hyphens":    15,   # > MAX_HYPHENS in hostname
        "redirect_params":      20,   # ?url=, ?goto=, ?redirect=
        "encoded_host":         25,   # percent-encoded chars in hostname

        # Lexical/keyword signals
        "trigger_keywords":     15,   # 'login', 'verify', 'secure', …
        "suspicious_tld":       20,   # .xyz, .tk, .ml, .top, …
        "digits_in_domain":     10,   # g00gle.com style
        "brand_in_subdomain":   40,   # paypal.evilsite.com
    }

    class Config:
        env_file = ".env"


settings = Settings()
