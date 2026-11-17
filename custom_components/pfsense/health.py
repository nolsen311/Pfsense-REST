"""Integration health: is it working, which part is not, and how to fix it.

Every poll reports into a :class:`HealthTracker`:

- the poll as a whole (live data, served from cache, or failed outright), and
- each *capability* ("check") the poll is made of — system, telemetry,
  services, DHCP, rules, ... — so one failing endpoint degrades the
  integration instead of breaking it.

Errors are reduced to a small set of *kinds* (unreachable, TLS, missing
privilege, ...) that both API backends map onto. The diagnostic entities show
the tracker's state, and :func:`async_sync_issues` turns it into Home
Assistant repair issues that say how to fix each kind (issue #14).
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass
import ssl
import time
from typing import Any
from urllib.parse import urlparse

import aiohttp

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import issue_registry as ir

from .const import DOMAIN
from .pypfsense import (
    BACKEND_PFREST,
    PfSenseAPIError,
    PfSenseAuthError,
    PfSenseConnectionError,
    PfSenseNotFoundError,
    PfSensePrivilegeError,
    PfSenseUnsupportedError,
)

# Error kinds -------------------------------------------------------------
KIND_UNREACHABLE = "unreachable"
KIND_TIMEOUT = "timeout"
KIND_TLS = "tls_error"
KIND_AUTH = "auth_failed"
KIND_PRIVILEGE = "privilege_missing"
KIND_API_MISSING = "api_missing"
KIND_API_ERROR = "api_error"
KIND_UNKNOWN = "unknown_error"
# Not a failure: the backend's API cannot provide this capability.
KIND_UNSUPPORTED = "unsupported"

# Overall status (the integration_status sensor's options) ---------------
STATUS_STARTING = "starting"
STATUS_OK = "ok"
STATUS_DEGRADED = "degraded"
STATUS_UNREACHABLE = "unreachable"
STATUS_OPTIONS = [
    STATUS_STARTING,
    STATUS_OK,
    STATUS_DEGRADED,
    STATUS_UNREACHABLE,
    KIND_TLS,
    KIND_AUTH,
    KIND_PRIVILEGE,
    KIND_API_MISSING,
    KIND_API_ERROR,
    KIND_UNKNOWN,
]

# A poll-level problem must persist this many polls before it becomes a repair
# issue, so a single dropped request does not raise an alarm.
FAILURES_BEFORE_ISSUE = 3
# Cached data older than this is no longer served as if it were current.
MIN_STALE_AFTER = 600
STALE_AFTER_INTERVALS = 5

# Repair issue ids (suffixed with the config entry id) --------------------
ISSUE_POLL_KINDS = {
    KIND_UNREACHABLE: "cannot_connect",
    KIND_TIMEOUT: "cannot_connect",
    KIND_TLS: "tls_error",
    KIND_API_MISSING: "api_missing",
    KIND_API_ERROR: "api_error",
    KIND_UNKNOWN: "api_error",
}
ISSUE_PRIVILEGE = "privilege_missing"
ISSUE_PFREST_EOL = "pfrest_eol"
_ALL_ISSUES = {*ISSUE_POLL_KINDS.values(), ISSUE_PRIVILEGE, ISSUE_PFREST_EOL}

# Service name of Netgate's Nexus controller, which serves the official API.
NEXUS_SERVICE = "pfnet-controller"
MIGRATION_URL = "https://github.com/nolsen311/Pfsense-REST/issues/11"


def classify(err: BaseException) -> str:
    """Reduce any poll exception to one of the error kinds."""
    if isinstance(err, PfSenseUnsupportedError):
        return KIND_UNSUPPORTED
    if isinstance(err, PfSenseAuthError):
        return KIND_AUTH
    if isinstance(err, PfSensePrivilegeError):
        return KIND_PRIVILEGE
    if isinstance(err, PfSenseNotFoundError):
        return KIND_API_MISSING
    if isinstance(err, PfSenseAPIError):
        return KIND_API_ERROR
    if isinstance(err, (TimeoutError, asyncio.TimeoutError)):
        return KIND_TIMEOUT
    if isinstance(err, PfSenseConnectionError):
        cause = err.__cause__
        while cause is not None:
            if isinstance(
                cause,
                (
                    aiohttp.ClientConnectorCertificateError,
                    aiohttp.ClientSSLError,
                    ssl.SSLError,
                ),
            ):
                return KIND_TLS
            if isinstance(cause, (TimeoutError, asyncio.TimeoutError)):
                return KIND_TIMEOUT
            cause = cause.__cause__
        if "timeout" in str(err).lower():
            return KIND_TIMEOUT
        return KIND_UNREACHABLE
    return KIND_UNKNOWN


@dataclass
class CheckResult:
    """The latest outcome of one capability check."""

    ok: bool = True
    kind: str | None = None
    message: str | None = None
    last_success: float | None = None
    consecutive_failures: int = 0

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly copy."""
        return {
            "ok": self.ok,
            "kind": self.kind,
            "message": self.message,
            "last_success": self.last_success,
            "consecutive_failures": self.consecutive_failures,
        }


class HealthTracker:
    """Health state for one config entry, shared by its coordinators."""

    def __init__(self, backend: str = BACKEND_PFREST, scan_interval: int = 30) -> None:
        """Start in the ``starting`` state."""
        self.backend = backend
        self.stale_after = max(MIN_STALE_AFTER, STALE_AFTER_INTERVALS * scan_interval)
        self.checks: dict[str, CheckResult] = {}
        self.last_attempt: float | None = None
        self.last_success: float | None = None
        self.consecutive_failures = 0
        self.poll_error_kind: str | None = None
        self.poll_error_message: str | None = None
        self.latency_ms: int | None = None
        self.using_cache = False
        self.cache_time: float | None = None
        self._listeners: list[Callable[[], None]] = []

    # ---------------------------------------------------------- listeners
    @callback
    def async_add_listener(
        self, update_callback: Callable[[], None]
    ) -> Callable[[], None]:
        """Call ``update_callback`` after every poll outcome; return a remover.

        The health entities use this rather than coordinator updates: Home
        Assistant does not notify coordinator listeners when a refresh fails
        right after another failed refresh, which is exactly when health
        matters.
        """
        self._listeners.append(update_callback)

        def remove() -> None:
            if update_callback in self._listeners:
                self._listeners.remove(update_callback)

        return remove

    @callback
    def async_notify(self) -> None:
        """Tell every listener that health changed."""
        for update_callback in list(self._listeners):
            update_callback()

    # ---------------------------------------------------------- recording
    def record_check(self, name: str, err: BaseException | None = None) -> None:
        """Record one capability's outcome for the current poll."""
        check = self.checks.setdefault(name, CheckResult())
        if err is None:
            check.ok, check.kind, check.message = True, None, None
            check.last_success = time.time()
            check.consecutive_failures = 0
        else:
            check.ok = False
            check.kind = classify(err)
            check.message = _short(err)
            check.consecutive_failures += 1

    def record_poll_success(self, latency_ms: int | None = None) -> None:
        """A poll returned live data (individual checks may still have failed)."""
        now = time.time()
        self.last_attempt = self.last_success = now
        self.consecutive_failures = 0
        self.poll_error_kind = self.poll_error_message = None
        self.latency_ms = latency_ms
        self.using_cache = False
        self.cache_time = None

    def record_poll_failure(self, err: BaseException) -> None:
        """The poll as a whole failed."""
        self.last_attempt = time.time()
        self.consecutive_failures += 1
        self.poll_error_kind = classify(err)
        self.poll_error_message = _short(err)
        self.latency_ms = None

    def record_cache_served(self, cache_time: float | None) -> None:
        """After a failed poll, cached data (captured at ``cache_time``) is shown."""
        self.using_cache = True
        self.cache_time = cache_time

    # ------------------------------------------------------------- derived
    @property
    def connected(self) -> bool:
        """True when the latest poll got live data from the firewall."""
        return self.last_success is not None and self.consecutive_failures == 0

    @property
    def failing_checks(self) -> list[str]:
        """Names of capabilities whose latest check failed."""
        return sorted(
            name
            for name, c in self.checks.items()
            if not c.ok and c.kind != KIND_UNSUPPORTED
        )

    @property
    def cache_age(self) -> float | None:
        """Seconds since the cached data being served was captured."""
        if not self.using_cache or self.cache_time is None:
            return None
        return max(0.0, time.time() - self.cache_time)

    def cache_too_old(self, cache_time: float | None) -> bool:
        """Whether data captured at ``cache_time`` is too old to show as current."""
        return cache_time is None or time.time() - cache_time > self.stale_after

    @property
    def status(self) -> str:
        """The single overall status shown by the integration_status sensor."""
        if self.last_attempt is None:
            return STATUS_STARTING
        if self.consecutive_failures:
            kind = self.poll_error_kind
            if kind in (KIND_UNREACHABLE, KIND_TIMEOUT):
                return STATUS_UNREACHABLE
            return kind or KIND_UNKNOWN
        if self.failing_checks:
            return STATUS_DEGRADED
        return STATUS_OK

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-friendly snapshot (diagnostics, entity attributes)."""
        return {
            "status": self.status,
            "backend": self.backend,
            "connected": self.connected,
            "last_attempt": self.last_attempt,
            "last_success": self.last_success,
            "consecutive_failures": self.consecutive_failures,
            "poll_error_kind": self.poll_error_kind,
            "poll_error_message": self.poll_error_message,
            "latency_ms": self.latency_ms,
            "using_cache": self.using_cache,
            "cache_age": self.cache_age,
            "stale_after": self.stale_after,
            "failing_checks": self.failing_checks,
            "checks": {name: c.as_dict() for name, c in sorted(self.checks.items())},
        }


def _short(err: BaseException, limit: int = 300) -> str:
    text = str(err) or type(err).__name__
    return text if len(text) <= limit else text[: limit - 1] + "…"


# ---------------------------------------------------------------- repairs


@callback
def async_sync_issues(
    hass: HomeAssistant,
    entry: ConfigEntry,
    tracker: HealthTracker,
    state: dict | None = None,
) -> None:
    """Create or clear this entry's repair issues to match ``tracker``.

    Auth failures are left to Home Assistant's reauth flow, which already
    surfaces them.
    """
    wanted: dict[str, tuple[ir.IssueSeverity, dict[str, str]]] = {}
    placeholders = _placeholders(entry, tracker)

    if tracker.consecutive_failures >= FAILURES_BEFORE_ISSUE:
        issue = ISSUE_POLL_KINDS.get(tracker.poll_error_kind or "")
        if issue:
            wanted[issue] = (ir.IssueSeverity.ERROR, placeholders)

    privilege_checks = [
        name
        for name, check in sorted(tracker.checks.items())
        if not check.ok and check.kind == KIND_PRIVILEGE
    ]
    if tracker.consecutive_failures and tracker.poll_error_kind == KIND_PRIVILEGE:
        privilege_checks = privilege_checks or ["system"]
    if privilege_checks:
        wanted[ISSUE_PRIVILEGE] = (
            ir.IssueSeverity.ERROR,
            {**placeholders, "checks": ", ".join(privilege_checks)},
        )

    if tracker.backend == BACKEND_PFREST and _nexus_running(state):
        wanted[ISSUE_PFREST_EOL] = (
            ir.IssueSeverity.WARNING,
            {**placeholders, "migration_url": MIGRATION_URL},
        )

    for issue in _ALL_ISSUES:
        issue_id = f"{issue}_{entry.entry_id}"
        if issue in wanted:
            severity, issue_placeholders = wanted[issue]
            ir.async_create_issue(
                hass,
                DOMAIN,
                issue_id,
                is_fixable=False,
                severity=severity,
                translation_key=issue,
                translation_placeholders=issue_placeholders,
            )
        else:
            ir.async_delete_issue(hass, DOMAIN, issue_id)


@callback
def async_clear_issues(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Remove every repair issue this entry may have raised (on unload)."""
    for issue in _ALL_ISSUES:
        ir.async_delete_issue(hass, DOMAIN, f"{issue}_{entry.entry_id}")


def _nexus_running(state: dict | None) -> bool:
    for service in (state or {}).get("services") or []:
        if isinstance(service, dict) and service.get("name") == NEXUS_SERVICE:
            return bool(service.get("status", service.get("running")))
    return False


def _placeholders(entry: ConfigEntry, tracker: HealthTracker) -> dict[str, str]:
    url = entry.data.get("url", "")
    parts = urlparse(url)
    port = str(parts.port or (443 if parts.scheme == "https" else 80)) if url else ""
    return {
        "name": entry.title or parts.hostname or "pfSense",
        "url": url,
        "port": port,
        "backend": tracker.backend,
        "error": tracker.poll_error_message or "",
    }
