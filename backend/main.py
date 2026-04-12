import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from config import settings
from models import ScanRequest, ScanResponse
from pipeline.threat_intel    import check_google_safe_browsing
from pipeline.whois_analyzer  import check_domain_age
from pipeline.lexical_analyzer import lexical_analyzer
from pipeline.scorer          import calculate_risk_score

# ── Logging setup ─────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
)
logger = logging.getLogger(__name__)


# ── App lifecycle ─────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("PhishGuard backend starting up…")
    if not settings.GOOGLE_SAFE_BROWSING_KEY:
        logger.warning(
            "GOOGLE_SAFE_BROWSING_KEY is not set. "
            "Threat intel check will be skipped. "
            "Set it in .env to enable Google Safe Browsing integration."
        )
    yield
    logger.info("PhishGuard backend shut down.")


# ── FastAPI app ───────────────────────────────────────────────

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "Multi-layer phishing and scam URL detection service. "
        "Combines Google Safe Browsing, WHOIS domain age analysis, "
        "and structural URL heuristics into a single risk score."
    ),
    lifespan=lifespan,
)

# Allow all origins so the PhishGuard frontend can call this API.
# In production: restrict to your actual frontend domain.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# ── Global exception handler ──────────────────────────────────

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error("Unhandled exception on %s: %s", request.url, exc, exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error. Please try again later."},
    )


# ── Routes ────────────────────────────────────────────────────

@app.get("/health")
async def health_check():
    """Simple liveness probe for load balancers / uptime monitors."""
    return {
        "status": "ok",
        "version": settings.APP_VERSION,
        "gsb_configured": bool(settings.GOOGLE_SAFE_BROWSING_KEY),
    }


@app.post("/scan", response_model=ScanResponse)
async def scan_url(request: ScanRequest) -> ScanResponse:
    """
    Main scan endpoint.

    Accepts a URL, runs it through the four-level analysis pipeline,
    and returns a structured risk assessment.

    Request body:
        {"url": "https://suspicious-site.xyz/login"}

    Response:
        {
          "url": "https://suspicious-site.xyz/login",
          "is_phishing": true,
          "risk_score": 85,
          "verdict": "PHISHING",
          "reasons": ["⚠ Фишинговые ключевые слова ...", ...],
          "details": { ... raw sub-results ... }
        }
    """
    url = request.url
    logger.info("Scanning URL: %s", url)

    # ── Levels 1 & 2 in parallel (both involve I/O) ───────────
    gsb_task   = check_google_safe_browsing(url)
    whois_task = check_domain_age(url)

    gsb_result, whois_result = await asyncio.gather(
        gsb_task,
        whois_task,
        return_exceptions=False,   # exceptions are caught inside each function
    )

    # ── Level 3: Lexical analysis (no I/O, runs instantly) ───
    lexical_features = lexical_analyzer.analyze(url)

    # ── Level 4: Aggregate into final score ──────────────────
    response = calculate_risk_score(
        url=url,
        gsb=gsb_result,
        whois=whois_result,
        lexical=lexical_features,
    )

    return response


@app.post("/batch", response_model=list[ScanResponse])
async def scan_batch(urls: list[str]) -> list[ScanResponse]:
    """
    Batch endpoint — scan up to 20 URLs in a single request.

    All URLs are scanned concurrently.  Input is a plain JSON array:
        ["https://url1.com", "https://url2.org"]
    """
    if len(urls) > 20:
        raise HTTPException(
            status_code=422,
            detail="Batch limit is 20 URLs per request.",
        )

    # Validate each URL via ScanRequest before processing
    validated: list[str] = []
    for raw in urls:
        try:
            req = ScanRequest(url=raw)
            validated.append(req.url)
        except Exception as exc:
            raise HTTPException(
                status_code=422,
                detail=f"Invalid URL {raw!r}: {exc}",
            )

    # Run all scans concurrently
    tasks = [
        scan_url(ScanRequest(url=u))
        for u in validated
    ]
    results = await asyncio.gather(*tasks)
    return list(results)
