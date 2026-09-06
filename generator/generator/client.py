"""Ingest API client."""

from __future__ import annotations

import time

import httpx
import structlog

logger = structlog.get_logger(__name__)


class IngestClient:
    def __init__(self, url: str, api_key: str, *, timeout: float = 15.0) -> None:
        self._url = url
        # The key travels in a header, never a query string: URLs end up in
        # access logs, proxies and browser history.
        self._headers = {"X-Ingest-Key": api_key, "Content-Type": "application/json"}
        self._client = httpx.Client(timeout=timeout)

    def send(self, events: list[dict], *, max_attempts: int = 4) -> dict | None:
        """POST a batch, retrying transient failures with backoff.

        Retries are safe because every event carries a stable `event_uid` and
        the backend deduplicates on it — a retry after a timeout that actually
        succeeded cannot double-count failed logins into a false brute-force
        alert.
        """
        payload = {"events": events}
        delay = 1.0

        for attempt in range(1, max_attempts + 1):
            try:
                response = self._client.post(self._url, json=payload, headers=self._headers)
                if response.status_code in (200, 202):
                    return response.json()

                if response.status_code in (401, 403):
                    # Not transient. Retrying a bad key just makes noise.
                    logger.error("ingest.rejected_credentials", status=response.status_code)
                    return None

                if 400 <= response.status_code < 500:
                    logger.error(
                        "ingest.rejected_payload",
                        status=response.status_code,
                        body=response.text[:300],
                    )
                    return None

                logger.warning("ingest.server_error", status=response.status_code, attempt=attempt)
            except httpx.RequestError as exc:
                logger.warning("ingest.transport_error", error=str(exc), attempt=attempt)

            if attempt < max_attempts:
                time.sleep(delay)
                delay = min(delay * 2, 30.0)

        logger.error("ingest.giving_up", attempts=max_attempts, batch_size=len(events))
        return None

    def wait_for_backend(self, health_url: str, *, timeout_seconds: float = 180.0) -> bool:
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            try:
                response = self._client.get(health_url, timeout=5.0)
                if response.status_code == 200:
                    return True
            except httpx.RequestError:
                pass
            time.sleep(3.0)
        return False

    def close(self) -> None:
        self._client.close()
