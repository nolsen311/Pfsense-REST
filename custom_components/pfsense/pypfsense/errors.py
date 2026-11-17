"""Exceptions shared by every pfSense API backend."""

from __future__ import annotations


class PfSenseError(Exception):
    """Base error for all pfSense REST API failures."""


class PfSenseConnectionError(PfSenseError):
    """Network-level failure: DNS, refused connection, TLS, timeout."""


class PfSenseAuthError(PfSenseError):
    """HTTP 401 - the API key is missing or invalid."""


class PfSensePrivilegeError(PfSenseError):
    """HTTP 403 - the key's user lacks privileges for this endpoint."""


class PfSenseNotFoundError(PfSenseError):
    """HTTP 404 - endpoint or resource does not exist (or wrong port / package missing)."""


class PfSenseAPIError(PfSenseError):
    """Any other non-2xx response. Carries ``code`` / ``response_id`` / ``message``."""

    def __init__(self, code: int, response_id: str, message: str) -> None:
        """Store the HTTP code, machine response id and human message."""
        self.code = code
        self.response_id = response_id
        self.message = message
        super().__init__(f"pfSense API {code} {response_id}: {message}")
