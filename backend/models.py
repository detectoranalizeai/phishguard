"""
models.py — Pydantic v2 schemas for request/response validation.

Using strict typing ensures corrupted or malformed input is rejected
before it ever reaches the pipeline, preventing downstream errors.
"""

from __future__ import annotations

from typing import Optional
from pydantic import BaseModel, HttpUrl, field_validator, model_validator
from urllib.parse import urlparse


# ── Inbound ──────────────────────────────────────────────────

class ScanRequest(BaseModel):
    """
    Validated scan request.

    Pydantic's HttpUrl already rejects malformed URLs.
    The custom validator normalises the scheme so callers
    can pass bare domains ("example.com") if they prefix with
    https:// manually — or we do it for them.
    """
    url: str

    @field_validator("url", mode="before")
    @classmethod
    def normalise_url(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("URL must not be empty")
        # Add https:// if no scheme present so urlparse works
        if not v.startswith(("http://", "https://")):
            v = "https://" + v
        parsed = urlparse(v)
        if not parsed.netloc:
            raise ValueError(f"Cannot extract hostname from: {v!r}")
        return v


# ── Internal pipeline result types ───────────────────────────

class ThreatIntelResult(BaseModel):
    checked: bool = False
    is_threat: bool = False
    threat_types: list[str] = []
    error: Optional[str] = None


class WhoisResult(BaseModel):
    checked: bool = False
    age_days: Optional[int] = None
    creation_date: Optional[str] = None
    registrar: Optional[str] = None
    error: Optional[str] = None


class LexicalFeatures(BaseModel):
    """Raw features extracted by LexicalAnalyzer before scoring."""
    has_ip_address:        bool = False
    has_at_symbol:         bool = False
    has_punycode:          bool = False
    has_non_ascii_host:    bool = False
    has_non_standard_port: bool = False
    has_encoded_host:      bool = False
    has_redirect_params:   bool = False
    has_digits_in_domain:  bool = False
    subdomain_count:       int  = 0
    url_length:            int  = 0
    domain_length:         int  = 0
    hyphen_count:          int  = 0
    trigger_keywords:      list[str] = []
    suspicious_tld:        bool = False
    brand_in_subdomain:    Optional[str] = None  # which brand was detected


# ── Outbound ─────────────────────────────────────────────────

class ScanResponse(BaseModel):
    """
    Final JSON returned to the caller.

    is_phishing  — boolean verdict (True if risk_score >= threshold)
    risk_score   — 0–100 aggregate score (higher = more dangerous)
    verdict      — human-readable label: SAFE | SUSPICIOUS | PHISHING
    reasons      — list of triggered checks (shown to the end-user)
    details      — raw sub-results from each pipeline stage (for debugging)
    """
    url:          str
    is_phishing:  bool
    risk_score:   int
    verdict:      str              # "SAFE" | "SUSPICIOUS" | "PHISHING"
    reasons:      list[str]
    details: dict = {}
