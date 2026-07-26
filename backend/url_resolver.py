"""
url_resolver.py

Разворачивает сокращённые/маскированные ссылки до финального реального URL
перед тем, как отдавать их на эвристический анализ.

Использование в бэкенде (FastAPI):

    from url_resolver import resolve_final_url

    @app.post("/analyze")
    async def analyze(payload: UrlPayload):
        original_url = payload.url
        final_url, redirect_chain, was_shortener = await resolve_final_url(original_url)

        # дальше кормим heuristics/URLhaus/RDAP уже final_url,
        # но в ответе показываем и original_url, и redirect_chain,
        # чтобы юзер видел, что ссылка была замаскирована
        ...
"""

import httpx
from urllib.parse import urlparse

# Известные сервисы сокращения/маскировки ссылок.
# Для них ОБЯЗАТЕЛЬНО разворачиваем редиректы — эвристика по самому
# домену сокращателя ничего не значит (dub.sh, bit.ly и т.п. сами
# по себе "чистые" домены с HTTPS).
KNOWN_SHORTENERS = {
    "dub.sh",
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "is.gd",
    "cutt.ly",
    "shorturl.at",
    "rebrand.ly",
    "buff.ly",
    "ow.ly",
    "s.id",
    "rb.gy",
    "short.io",
    "lnkd.in",
    "tiny.cc",
    "clck.ru",
    "vk.cc",
    "qps.ru",
}

MAX_REDIRECTS = 10
TIMEOUT_SECONDS = 5.0


def _domain(url: str) -> str:
    try:
        return urlparse(url).netloc.lower().split(":")[0]
    except Exception:
        return ""


async def resolve_final_url(url: str):
    """
    Возвращает (final_url, redirect_chain, was_shortener).

    - final_url: конечный URL после всех редиректов (или исходный,
      если редиректов не было / домен не в списке сокращателей)
    - redirect_chain: список всех промежуточных URL по порядку
    - was_shortener: True, если исходный домен — известный сокращатель
    """
    original_domain = _domain(url)
    was_shortener = original_domain in KNOWN_SHORTENERS

    # Если домен не сокращатель — всё равно можно попробовать
    # HEAD-запрос на случай скрытого редиректа, но без давления,
    # это не обязательно. Тут делаем это всегда, для надёжности.
    redirect_chain = [url]
    current_url = url

    try:
        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=TIMEOUT_SECONDS,
            headers={"User-Agent": "Mozilla/5.0 (compatible; PhishGuardBot/1.0)"},
        ) as client:
            for _ in range(MAX_REDIRECTS):
                try:
                    resp = await client.get(current_url)
                except httpx.RequestError:
                    # сервер недоступен / таймаут / битая ссылка —
                    # возвращаем то, что успели разузнать
                    break

                if resp.status_code in (301, 302, 303, 307, 308):
                    location = resp.headers.get("location")
                    if not location:
                        break
                    # относительные редиректы -> абсолютные
                    if location.startswith("/"):
                        parsed = urlparse(current_url)
                        location = f"{parsed.scheme}://{parsed.netloc}{location}"
                    current_url = location
                    redirect_chain.append(current_url)
                else:
                    break
    except Exception:
        # любая непредвиденная ошибка — не роняем анализ,
        # просто работаем с тем, что есть
        pass

    return current_url, redirect_chain, was_shortener
