"""
pipeline/scorer.py — Level 4: Risk Score Aggregation

Takes the raw outputs from all three earlier levels and computes a
final risk_score in [0, 100].

Design decisions
────────────────
- Additive scoring with a hard 100-cap: each triggered condition adds
  its configured weight.  No single condition can exceed the cap.

- Short-circuit on GSB hit: if Google Safe Browsing confirmed a threat,
  we force the score to ≥ 90 regardless of other signals, because a
  live GSB match is essentially certain evidence of malice.

- Human-readable reasons: every triggered condition maps to a
  user-facing string.  These are the "reasons" field in the API
  response — they help end users understand WHY a URL was flagged.

- Verdict labels:
    SAFE        risk_score < SUSPICIOUS_MIN
    SUSPICIOUS  SUSPICIOUS_MIN ≤ risk_score < PHISHING_THRESHOLD
    PHISHING    risk_score ≥ PHISHING_THRESHOLD
"""

import logging
from typing import Optional

from config import settings
from models import (
    ThreatIntelResult,
    WhoisResult,
    LexicalFeatures,
    ScanResponse,
)

logger = logging.getLogger(__name__)

W = settings.WEIGHTS  # alias for readability


def _verdict(score: int) -> str:
    if score >= settings.PHISHING_THRESHOLD:
        return "PHISHING"
    if score >= settings.SUSPICIOUS_MIN:
        return "SUSPICIOUS"
    return "SAFE"


def calculate_risk_score(
    url: str,
    gsb:     ThreatIntelResult,
    whois:   WhoisResult,
    lexical: LexicalFeatures,
) -> ScanResponse:
    """
    Aggregates evidence from all pipeline levels and produces the
    final ScanResponse.

    Args:
        url:     The original (or normalised) URL.
        gsb:     Result from Google Safe Browsing check (Level 1).
        whois:   Result from WHOIS domain age lookup  (Level 2).
        lexical: Structural features from LexicalAnalyzer (Level 3).

    Returns:
        ScanResponse with all fields populated.
    """
    score: int = 0
    reasons: list[str] = []

    # ── Level 1: Threat Intelligence ─────────────────────────
    if gsb.is_threat:
        # Force minimum score to 90 — GSB match = confirmed threat
        threat_str = ", ".join(gsb.threat_types)
        score = max(score, 90)
        reasons.append(
            f"🚨 Обнаружено в Google Safe Browsing: {threat_str}"
        )
        logger.warning("GSB confirmed threat for %s: %s", url, threat_str)

    # ── Level 2: WHOIS Domain Age ────────────────────────────
    if whois.checked and whois.age_days is not None:
        age = whois.age_days
        if age < settings.DOMAIN_AGE_VERY_NEW:
            score += W["domain_very_new"]
            reasons.append(
                f"🚨 Домен зарегистрирован {age} дн. назад — крайне подозрительно"
            )
        elif age < settings.DOMAIN_AGE_NEW:
            score += W["domain_new"]
            reasons.append(
                f"⚠ Домен зарегистрирован {age} дн. назад — менее 30 дней (типично для фишинга)"
            )
        elif age < settings.DOMAIN_AGE_RECENT:
            score += W["domain_recent"]
            reasons.append(
                f"Домен создан менее 90 дней назад ({age} дн.)"
            )
    elif not whois.checked:
        # WHOIS failure is itself a mild signal — legit domains are
        # usually in WHOIS; many throwaway phishing domains aren't
        score += 5
        reasons.append("WHOIS данные недоступны")

    # ── Level 3: Lexical / Structural Features ───────────────

    if lexical.has_ip_address:
        score += W["ip_in_url"]
        reasons.append("🚨 IP-адрес вместо доменного имени")

    if lexical.has_at_symbol:
        score += W["at_symbol"]
        reasons.append("🚨 Символ @ скрывает настоящий адрес (http://brand@evil.com)")

    if lexical.has_punycode:
        score += W["punycode"]
        reasons.append("🚨 Punycode-кодирование (xn--) — возможная IDN-гомоглиф атака")

    if lexical.has_non_ascii_host:
        score += W["non_ascii_host"]
        reasons.append("🚨 Нестандартные Unicode-символы в домене — омоглифная атака")

    if lexical.has_non_standard_port:
        score += W["non_standard_port"]
        reasons.append("⚠ Нестандартный порт — легитимные сервисы используют 80/443")

    if lexical.has_encoded_host:
        score += W["encoded_host"]
        reasons.append("⚠ URL-кодирование в домене — попытка скрыть адрес")

    if lexical.has_redirect_params:
        score += W["redirect_params"]
        reasons.append("⚠ Параметры открытого редиректа (?url=, ?goto=, ?redirect=...)")

    if lexical.subdomain_count > settings.MAX_SUBDOMAINS:
        score += W["excessive_subdomains"]
        reasons.append(
            f"⚠ Аномальное число поддоменов ({lexical.subdomain_count}) — "
            f"типичный приём маскировки"
        )

    if lexical.url_length > settings.MAX_URL_LENGTH:
        score += W["long_url"]
        reasons.append(f"Аномально длинный URL ({lexical.url_length} символов)")

    if lexical.domain_length > settings.MAX_DOMAIN_LENGTH:
        score += W["long_domain"]
        reasons.append(
            f"Очень длинный домен ({lexical.domain_length} символов) — нетипично для легитимных сайтов"
        )

    if lexical.hyphen_count > settings.MAX_HYPHENS:
        score += W["excessive_hyphens"]
        reasons.append(f"Чрезмерное количество дефисов в домене ({lexical.hyphen_count})")

    if lexical.trigger_keywords:
        score += W["trigger_keywords"]
        kw_str = ", ".join(lexical.trigger_keywords[:5])
        reasons.append(f"⚠ Фишинговые ключевые слова в URL: {kw_str}")

    if lexical.suspicious_tld:
        score += W["suspicious_tld"]
        reasons.append("⚠ Подозрительная доменная зона — часто используется мошенниками")

    if lexical.has_digits_in_domain:
        score += W["digits_in_domain"]
        reasons.append("Цифры в домене (g00gle, sberbank1...)")

    if lexical.brand_in_subdomain:
        score += W["brand_in_subdomain"]
        reasons.append(
            f"🚨 Бренд «{lexical.brand_in_subdomain}» использован как поддомен "
            f"чужого сайта (brand.com.evil.ru)"
        )

    # ── Final score normalisation ────────────────────────────
    score = min(score, 100)
    verdict = _verdict(score)
    is_phishing = score >= settings.PHISHING_THRESHOLD

    logger.info(
        "Score for %s: %d (%s), triggers=%d",
        url, score, verdict, len(reasons),
    )

    # Build detail dict for debugging / transparency
    details = {
        "threat_intel": gsb.model_dump(),
        "whois":        whois.model_dump(),
        "lexical":      lexical.model_dump(),
    }

    return ScanResponse(
        url=url,
        is_phishing=is_phishing,
        risk_score=score,
        verdict=verdict,
        reasons=reasons,
        details=details,
    )
