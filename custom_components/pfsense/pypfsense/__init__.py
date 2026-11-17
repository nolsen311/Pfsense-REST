"""Async pfSense API clients.

Two backends implement :class:`PfSenseBackend`:

- ``pfrest`` — :class:`PfRestClient`, the community REST API package v2.
- ``netgate`` — :class:`NetgateClient`, Netgate's official (Nexus) API.

:func:`client_from_config` picks the backend from a config-entry mapping, so the
integration never names a concrete client class. ``Client`` is kept as an alias
of :class:`PfRestClient` for existing callers and tests.
"""

from __future__ import annotations

import aiohttp

from .backend import BACKEND_NETGATE, BACKEND_PFREST, BACKENDS, PfSenseBackend
from .errors import (
    PfSenseAPIError,
    PfSenseAuthError,
    PfSenseConnectionError,
    PfSenseError,
    PfSenseNotFoundError,
    PfSensePrivilegeError,
    PfSenseUnsupportedError,
)
from .netgate import NetgateClient
from .pfrest import (
    API_BASE,
    AUTH_API_KEY,
    AUTH_BASIC,
    AUTH_JWT,
    DEFAULT_TIMEOUT,
    PfRestClient,
    _build_telemetry,
)
from .util import dict_get

Client = PfRestClient

CONF_BACKEND = "backend"

__all__ = [
    "API_BASE",
    "AUTH_API_KEY",
    "AUTH_BASIC",
    "AUTH_JWT",
    "BACKENDS",
    "BACKEND_NETGATE",
    "BACKEND_PFREST",
    "CONF_BACKEND",
    "DEFAULT_TIMEOUT",
    "Client",
    "NetgateClient",
    "PfRestClient",
    "PfSenseAPIError",
    "PfSenseAuthError",
    "PfSenseBackend",
    "PfSenseConnectionError",
    "PfSenseError",
    "PfSenseNotFoundError",
    "PfSensePrivilegeError",
    "PfSenseUnsupportedError",
    "_build_telemetry",
    "client_from_config",
    "dict_get",
]


def client_from_config(
    url: str,
    session: aiohttp.ClientSession,
    data: dict,
    verify_ssl: bool,
) -> PfSenseBackend:
    """Build the backend client described by a config-entry ``data`` mapping.

    ``backend`` selects the API (default ``"pfrest"``, so entries created before
    the key existed keep working). For pfrest, ``auth_method`` (default
    ``"api_key"``) and the credential keys (``api_key`` / ``username`` /
    ``password``) pick the auth scheme. Shared by the integration setup and the
    config flow so the branching lives in one place.
    """
    backend = data.get(CONF_BACKEND, BACKEND_PFREST)
    if backend == BACKEND_PFREST:
        return PfRestClient(
            url,
            session,
            auth_method=data.get("auth_method", AUTH_API_KEY),
            api_key=data.get("api_key"),
            username=data.get("username"),
            password=data.get("password"),
            verify_ssl=verify_ssl,
        )
    if backend == BACKEND_NETGATE:
        return NetgateClient(
            url,
            session,
            username=data.get("username"),
            password=data.get("password"),
            verify_ssl=verify_ssl,
        )
    raise PfSenseError(f"unknown pfSense API backend {backend!r}")
