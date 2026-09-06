"""FastAPI application factory."""

from __future__ import annotations

import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.api.v1.api import api_router
from app.core.config import Settings, get_settings
from app.core.logging import configure_logging, get_logger

logger = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class DetectionCoverage:
    """What the running process can actually detect.

    Returned rather than only logged, so the check is testable without
    depending on logging configuration.
    """

    registered: tuple[str, ...]
    enabled_in_database: tuple[str, ...] | None  # None when the DB was not consulted
    missing_implementations: tuple[str, ...]
    implemented_but_not_enabled: tuple[str, ...]

    @property
    def healthy(self) -> bool:
        return bool(self.registered) and not self.missing_implementations


def check_detection_coverage(settings: Settings) -> DetectionCoverage:
    """Compare implemented rules against the rules the database expects to run.

    This exists because of a real defect: the rule modules were imported by the
    seeding CLI and the test fixtures, but by nothing the API process itself
    loaded. The seed process wrote eight rule rows; the API process then had an
    empty registry and quietly evaluated nothing, logging one line per rule per
    ingest batch - noise that read as a warning rather than an outage.
    """
    from app.detection.registry import registered_keys

    registered = registered_keys()

    enabled: frozenset[str] | None = None
    # Skipped under tests, where the configured database is not the one the
    # fixtures use. Never allowed to raise: this is diagnostics, not startup.
    if settings.ENVIRONMENT != "test":
        try:
            from sqlalchemy import select

            from app.db.session import get_session_factory
            from app.models.detection import DetectionRule as DetectionRuleModel

            session = get_session_factory()()
            try:
                enabled = frozenset(
                    session.execute(
                        select(DetectionRuleModel.rule_key).where(
                            DetectionRuleModel.enabled.is_(True)
                        )
                    )
                    .scalars()
                    .all()
                )
            finally:
                session.close()
        except Exception as exc:
            logger.warning(
                "application.rule_consistency_check_skipped",
                reason=type(exc).__name__,
                detail=str(exc).splitlines()[0][:160],
            )
            enabled = None

    return DetectionCoverage(
        registered=tuple(sorted(registered)),
        enabled_in_database=None if enabled is None else tuple(sorted(enabled)),
        missing_implementations=() if enabled is None else tuple(sorted(enabled - registered)),
        implemented_but_not_enabled=(
            () if enabled is None else tuple(sorted(registered - enabled))
        ),
    )


def _report_detection_coverage(coverage: DetectionCoverage) -> None:
    """Log the coverage result. One explicit line, so zero rules cannot hide."""
    if not coverage.registered:
        logger.error(
            "application.no_detection_rules_registered",
            hint=(
                "The detection registry is empty; ingested events will not be "
                "evaluated. app.detection.rules failed to import."
            ),
        )
        return

    logger.info(
        "application.detection_rules_active",
        count=len(coverage.registered),
        rules=list(coverage.registered),
    )
    if coverage.missing_implementations:
        logger.error(
            "application.enabled_rules_without_implementation",
            rules=list(coverage.missing_implementations),
            hint="Enabled in the database but no code implements them.",
        )
    if coverage.implemented_but_not_enabled:
        logger.warning(
            "application.implemented_rules_not_enabled",
            rules=list(coverage.implemented_but_not_enabled),
            hint="Implemented but disabled or absent from the database.",
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings: Settings = app.state.settings
    logger.info(
        "application.startup",
        environment=settings.ENVIRONMENT,
        api_prefix=settings.API_V1_PREFIX,
    )
    _report_detection_coverage(check_detection_coverage(settings))
    yield
    logger.info("application.shutdown")


BODYLESS_METHODS = frozenset({"GET", "HEAD", "DELETE", "OPTIONS", "TRACE"})


def evaluate_request_size(
    *,
    method: str,
    content_length: str | None,
    transfer_encoding: str | None,
    limit_bytes: int,
) -> tuple[int, str] | None:
    """Decide whether a request should be refused on size alone.

    Returns `(status_code, detail)` to reject, or None to allow.

    Schema validation bounds the *shape* of a payload but only after the whole
    body has been read and parsed: the ingest schema permits roughly 125 MB
    (500 events x 64 keys x 4096 characters). This decides from the headers,
    before anything is buffered.

    Extracted as a plain function because the chunked-transfer branch cannot be
    reached through a test client — httpx always sets Content-Length — and an
    untestable branch in a security control is not worth having.
    """
    if method.upper() in BODYLESS_METHODS:
        return None

    if content_length is None:
        if (transfer_encoding or "").lower() == "chunked":
            # This API only receives JSON from its own clients, all of which
            # send a length. An unmeasurable body would leave the ceiling
            # unenforceable, so it is refused rather than streamed.
            return (
                status.HTTP_411_LENGTH_REQUIRED,
                "A Content-Length header is required.",
            )
        return None

    try:
        declared = int(content_length)
    except ValueError:
        return (status.HTTP_400_BAD_REQUEST, "Malformed Content-Length header.")

    if declared < 0:
        return (status.HTTP_400_BAD_REQUEST, "Malformed Content-Length header.")

    if declared > limit_bytes:
        return (
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            f"Request body exceeds the {limit_bytes // (1024 * 1024)} MB limit.",
        )
    return None


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.LOG_LEVEL, json_output=settings.is_production)

    app = FastAPI(
        title=settings.PROJECT_NAME,
        version="1.0.0",
        description=(
            "SOC Analyst Dashboard API. All telemetry served by this API is "
            "synthetic; all response actions are simulated."
        ),
        lifespan=lifespan,
        # Interactive docs are a reconnaissance aid on an internet-facing
        # deployment, so they are disabled outside development.
        docs_url=None if settings.is_production else "/docs",
        redoc_url=None if settings.is_production else "/redoc",
        openapi_url=None if settings.is_production else "/openapi.json",
    )
    app.state.settings = settings

    # ---------------------------------------------------------------- CORS
    app.add_middleware(
        CORSMiddleware,
        # Explicit origins. allow_credentials with "*" is rejected by browsers
        # and would be wrong here regardless: the refresh cookie is credentialed.
        allow_origins=settings.cors_origin_list,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-Ingest-Key"],
        max_age=600,
    )

    # ------------------------------------------------------- request size cap
    @app.middleware("http")
    async def limit_request_body(request: Request, call_next):
        rejection = evaluate_request_size(
            method=request.method,
            content_length=request.headers.get("content-length"),
            transfer_encoding=request.headers.get("transfer-encoding"),
            limit_bytes=settings.MAX_REQUEST_BODY_BYTES,
        )
        if rejection is not None:
            code, detail = rejection
            logger.warning(
                "request.rejected_by_size_policy",
                path=request.url.path,
                status_code=code,
                declared=request.headers.get("content-length"),
                limit_bytes=settings.MAX_REQUEST_BODY_BYTES,
            )
            return JSONResponse(status_code=code, content={"detail": detail})
        return await call_next(request)

    # ------------------------------------------------- correlation + headers
    @app.middleware("http")
    async def request_context(request: Request, call_next):
        correlation_id = uuid.uuid4().hex[:12]
        request.state.correlation_id = correlation_id
        response = await call_next(request)
        response.headers["X-Correlation-ID"] = correlation_id

        # Defence-in-depth headers. The API returns JSON, so most of these
        # matter only if a browser is ever tricked into rendering a response,
        # which is exactly the case they are for.
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        )
        response.headers["Cache-Control"] = "no-store"
        if settings.COOKIE_SECURE:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )
        return response

    # -------------------------------------------------------- error handling
    @app.exception_handler(StarletteHTTPException)
    async def http_exception_handler(request: Request, exc: StarletteHTTPException):
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "detail": exc.detail,
                "correlation_id": getattr(request.state, "correlation_id", None),
            },
            headers=getattr(exc, "headers", None),
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        # Field-level errors are returned (they help a legitimate client) but the
        # submitted input is not echoed back, so a payload containing a password
        # cannot end up in an error body or a browser console.
        fields = [
            {"field": ".".join(str(p) for p in err["loc"][1:]), "message": err["msg"]}
            for err in exc.errors()
        ]
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "detail": "Request validation failed.",
                "errors": fields,
                "correlation_id": getattr(request.state, "correlation_id", None),
            },
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception):
        correlation_id = getattr(request.state, "correlation_id", None)
        # Full detail to the log, nothing to the client. A stack trace in an
        # HTTP response tells an attacker the framework, file layout and often
        # the database schema.
        logger.exception(
            "request.unhandled_exception",
            path=request.url.path,
            method=request.method,
            correlation_id=correlation_id,
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "detail": "An internal error occurred.",
                "correlation_id": correlation_id,
            },
        )

    app.include_router(api_router, prefix=settings.API_V1_PREFIX)
    return app


# Module-level `app` is created lazily via PEP 562. `uvicorn app.main:app`
# resolves it through this hook, while the test suite can import `create_app`
# without instantiating settings that would demand a real SECRET_KEY.
_app: FastAPI | None = None


def __getattr__(name: str) -> FastAPI:
    global _app
    if name == "app":
        if _app is None:
            _app = create_app()
        return _app
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
