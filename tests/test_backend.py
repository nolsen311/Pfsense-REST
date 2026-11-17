"""Tests for backend selection and the PfSenseBackend interface."""

import inspect

import pytest

from custom_components.pfsense.pypfsense import (
    BACKEND_NETGATE,
    BACKEND_PFREST,
    Client,
    PfRestClient,
    PfSenseBackend,
    PfSenseError,
    client_from_config,
)

BASE = "https://pf.example:8444"


def _public_coroutines(cls: type) -> set[str]:
    return {
        name
        for name, member in vars(cls).items()
        if not name.startswith("_") and inspect.iscoroutinefunction(member)
    }


def test_client_alias_is_pfrest() -> None:
    """``Client`` stays importable for existing callers."""
    assert Client is PfRestClient


def test_interface_matches_pfrest_public_surface() -> None:
    """The interface declares exactly PfRestClient's public coroutines.

    A method added to a client but not to the interface (or vice versa) would
    let the backends drift apart; keep the two in lockstep.
    """
    assert _public_coroutines(PfSenseBackend) == _public_coroutines(PfRestClient)


def test_pfrest_is_a_backend() -> None:
    """The runtime-checkable protocol accepts a PfRestClient instance."""
    client = PfRestClient(BASE, object(), auth_method="api_key", api_key="k")
    assert isinstance(client, PfSenseBackend)


@pytest.mark.parametrize(
    "data", [{"api_key": "k"}, {"backend": BACKEND_PFREST, "api_key": "k"}]
)
def test_client_from_config_defaults_to_pfrest(data: dict) -> None:
    """Entries without a ``backend`` key (all existing ones) get pfrest."""
    assert isinstance(client_from_config(BASE, object(), data, True), PfRestClient)


def test_client_from_config_netgate_not_built_yet() -> None:
    """The Netgate backend is declared but not implemented in this phase."""
    with pytest.raises(NotImplementedError):
        client_from_config(BASE, object(), {"backend": BACKEND_NETGATE}, True)


def test_client_from_config_unknown_backend() -> None:
    """An unknown backend is a clear error, not a silent pfrest fallback."""
    with pytest.raises(PfSenseError):
        client_from_config(BASE, object(), {"backend": "bogus"}, True)
