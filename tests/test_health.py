"""Health checks: status, entities, repair issues and diagnostics (issue #14)."""

from contextlib import contextmanager
import ssl
import time
from unittest.mock import AsyncMock, patch

import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.pfsense.const import CONF_API_KEY, COORDINATOR, DOMAIN, HEALTH
from custom_components.pfsense.diagnostics import async_get_config_entry_diagnostics
from custom_components.pfsense.health import (
    FAILURES_BEFORE_ISSUE,
    KIND_API_ERROR,
    KIND_API_MISSING,
    KIND_AUTH,
    KIND_PRIVILEGE,
    KIND_TIMEOUT,
    KIND_TLS,
    KIND_UNKNOWN,
    KIND_UNREACHABLE,
    HealthTracker,
    classify,
)
from custom_components.pfsense.pypfsense import (
    PfSenseAPIError,
    PfSenseAuthError,
    PfSenseConnectionError,
    PfSenseNotFoundError,
    PfSensePrivilegeError,
)
from homeassistant.config_entries import ConfigEntryState
from homeassistant.const import CONF_URL, CONF_VERIFY_SSL, STATE_OFF, STATE_ON
from homeassistant.core import HomeAssistant
from homeassistant.helpers import issue_registry as ir

ENTRY_ID = "health_entry"
STATUS = "sensor.router_local_integration_status"
CONNECTED = "binary_sensor.router_local_api_connected"
LAST_POLL = "sensor.router_local_last_successful_poll"
CARP = "binary_sensor.router_local_carp_status"


def _client():
    client = AsyncMock()
    client.get_system_info.return_value = {
        "hostname": "router",
        "domain": "local",
        "netgate_device_id": "mock_id_12345",
        "serial": "1",
        "platform": "pfSense",
    }
    client.get_host_firmware_version.return_value = {
        "platform": "pfSense",
        "firmware": {"version": "26.07-RELEASE"},
    }
    client.get_telemetry.return_value = {
        "interfaces": {
            "wan": {"ifname": "wan", "descr": "WAN", "inbytes": 1000, "outbytes": 1000}
        },
        "gateways": {},
        "openvpn": {"servers": {}},
        "system": {"load_average": {}},
        "cpu": {},
        "memory": {},
        "mbuf": {},
        "filesystems": [],
        "wan_ip": "203.0.113.7",
    }
    client.get_services.return_value = [{"name": "unbound", "status": True}]
    client.get_carp_interfaces.return_value = []
    client.get_carp_status.return_value = False
    client.get_dhcp_leases.return_value = []
    client.get_dns_servers.return_value = []
    client.get_filter_rules.return_value = []
    client.get_nat_port_forward_rules.return_value = []
    client.get_nat_outbound_rules.return_value = []
    return client


def _entry():
    return MockConfigEntry(
        domain=DOMAIN,
        version=4,
        title="router.local",
        unique_id="mock_id_12345",
        data={
            CONF_URL: "https://192.168.1.1:8444",
            CONF_API_KEY: "secret-key",
            CONF_VERIFY_SSL: False,
        },
        options={"device_tracker_enabled": False},
        entry_id=ENTRY_ID,
    )


@contextmanager
def _patched(client, cache=None):
    with (
        patch("custom_components.pfsense.client_from_config", return_value=client),
        patch("custom_components.pfsense.async_load_cache", return_value=cache),
        patch("custom_components.pfsense.async_save_cache"),
    ):
        yield


async def _setup(hass, client, cache=None):
    entry = _entry()
    entry.add_to_hass(hass)
    with _patched(client, cache):
        await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()
    return entry


def _issue(hass, issue):
    return ir.async_get(hass).async_get_issue(DOMAIN, f"{issue}_{ENTRY_ID}")


async def _refresh(hass, client, cache=None, times=1):
    coordinator = hass.data[DOMAIN][ENTRY_ID][COORDINATOR]
    with _patched(client, cache):
        for _ in range(times):
            await coordinator.async_refresh()
        await hass.async_block_till_done()


# ------------------------------------------------------------- classify


def _wrapped(cause: BaseException) -> PfSenseConnectionError:
    err = PfSenseConnectionError("boom")
    err.__cause__ = cause
    return err


@pytest.mark.parametrize(
    ("err", "kind"),
    [
        (PfSenseAuthError("x"), KIND_AUTH),
        (PfSensePrivilegeError("x"), KIND_PRIVILEGE),
        (PfSenseNotFoundError("x"), KIND_API_MISSING),
        (PfSenseAPIError(500, "E", "x"), KIND_API_ERROR),
        (TimeoutError(), KIND_TIMEOUT),
        (PfSenseConnectionError("timeout contacting https://x"), KIND_TIMEOUT),
        (_wrapped(ssl.SSLError("bad cert")), KIND_TLS),
        (PfSenseConnectionError("Connection refused"), KIND_UNREACHABLE),
        (ValueError("x"), KIND_UNKNOWN),
    ],
)
def test_classify(err, kind) -> None:
    """Every failure maps onto one actionable kind."""
    assert classify(err) == kind


def test_tracker_status_transitions() -> None:
    """Starting -> ok -> degraded -> unreachable -> ok."""
    tracker = HealthTracker()
    assert tracker.status == "starting"
    tracker.record_check("services")
    tracker.record_poll_success(12)
    assert (tracker.status, tracker.connected) == ("ok", True)
    tracker.record_check("services", PfSensePrivilegeError("no"))
    assert tracker.status == "degraded"
    assert tracker.failing_checks == ["services"]
    tracker.record_poll_failure(PfSenseConnectionError("Connection refused"))
    assert (tracker.status, tracker.connected) == ("unreachable", False)
    tracker.record_check("services")
    tracker.record_poll_success(10)
    assert tracker.status == "ok"


def test_stale_after_scales_with_scan_interval() -> None:
    """Cache is served for at least 10 minutes, or 5 scan intervals."""
    assert HealthTracker(scan_interval=30).stale_after == 600
    assert HealthTracker(scan_interval=300).stale_after == 1500
    tracker = HealthTracker()
    assert not tracker.cache_too_old(time.time() - 60)
    assert tracker.cache_too_old(time.time() - 3600)
    assert tracker.cache_too_old(None)


# ------------------------------------------------------- integration


async def test_healthy_setup_exposes_health_entities(hass: HomeAssistant) -> None:
    """A clean poll shows ok, connected, a timestamp, and no repair issues."""
    await _setup(hass, _client())
    assert hass.states.get(STATUS).state == "ok"
    assert hass.states.get(CONNECTED).state == STATE_ON
    assert hass.states.get(LAST_POLL).state not in ("unknown", "unavailable")
    assert hass.states.get("button.router_local_run_health_check") is not None
    assert not ir.async_get(hass).issues


async def test_privilege_error_degrades_instead_of_reauth(hass: HomeAssistant) -> None:
    """A 403 on one capability no longer sends the user to re-enter credentials."""
    client = _client()
    client.get_services.side_effect = PfSensePrivilegeError("forbidden")
    entry = await _setup(hass, client)

    assert entry.state is ConfigEntryState.LOADED
    assert not [
        f
        for f in hass.config_entries.flow.async_progress()
        if f["context"]["source"] == "reauth"
    ]
    status = hass.states.get(STATUS)
    assert status.state == "degraded"
    assert status.attributes["failing_checks"] == ["services"]
    assert status.attributes["checks"]["services"] == KIND_PRIVILEGE
    assert hass.states.get(CONNECTED).state == STATE_ON
    issue = _issue(hass, "privilege_missing")
    assert issue is not None
    assert issue.translation_placeholders["checks"] == "services"
    # The rest of the poll still landed.
    assert hass.data[DOMAIN][ENTRY_ID][COORDINATOR].data["services"] == []
    assert hass.states.get(CARP).state == STATE_OFF

    client.get_services.side_effect = None
    await _refresh(hass, client)
    assert hass.states.get(STATUS).state == "ok"
    assert _issue(hass, "privilege_missing") is None


async def test_failed_read_keeps_previous_value(hass: HomeAssistant) -> None:
    """A capability that fails after a good poll keeps its last good data."""
    client = _client()
    await _setup(hass, client)
    first_time = hass.data[DOMAIN][ENTRY_ID][COORDINATOR].data["telemetry_update_time"]

    client.get_telemetry.side_effect = PfSenseAPIError(500, "E", "x")
    await _refresh(hass, client)
    data = hass.data[DOMAIN][ENTRY_ID][COORDINATOR].data
    assert data["telemetry"]["wan_ip"] == "203.0.113.7"
    # Rates must later be computed from when telemetry was really fetched.
    assert data["telemetry_update_time"] == first_time
    assert hass.states.get(STATUS).state == "degraded"


async def test_unreachable_raises_repair_after_threshold(hass: HomeAssistant) -> None:
    """Repeated connection failures create a fixable-by-user repair, then clear it."""
    client = _client()
    await _setup(hass, client)
    client.get_system_info.side_effect = PfSenseConnectionError("Connection refused")
    recent_cache = dict(hass.data[DOMAIN][ENTRY_ID][COORDINATOR].data)

    await _refresh(hass, client, cache=recent_cache, times=FAILURES_BEFORE_ISSUE - 1)
    assert _issue(hass, "cannot_connect") is None
    status = hass.states.get(STATUS)
    assert status.state == "unreachable"
    # Updated even though the coordinator does not announce back-to-back failures.
    assert status.attributes["consecutive_failures"] == FAILURES_BEFORE_ISSUE - 1
    assert status.attributes["using_cache"] is True
    assert hass.states.get(CONNECTED).state == STATE_OFF
    # Recent cache is still shown.
    assert hass.states.get(CARP).state == STATE_OFF

    await _refresh(hass, client, cache=recent_cache)
    issue = _issue(hass, "cannot_connect")
    assert issue is not None
    assert issue.translation_placeholders["port"] == "8444"

    client.get_system_info.side_effect = None
    await _refresh(hass, client)
    assert _issue(hass, "cannot_connect") is None
    assert hass.states.get(STATUS).state == "ok"


async def test_stale_cache_makes_entities_unavailable(hass: HomeAssistant) -> None:
    """Old cache is not shown as current; health entities stay available."""
    client = _client()
    await _setup(hass, client)
    old_cache = dict(hass.data[DOMAIN][ENTRY_ID][COORDINATOR].data)
    old_cache["update_time"] = time.time() - 7200

    client.get_system_info.side_effect = PfSenseConnectionError("Connection refused")
    await _refresh(hass, client, cache=old_cache)

    assert hass.states.get(CARP).state == "unavailable"
    assert hass.states.get(STATUS).state == "unreachable"
    assert hass.states.get(CONNECTED).state == STATE_OFF


async def test_startup_serves_old_cache(hass: HomeAssistant) -> None:
    """At startup any cache is used, so the integration loads while unreachable."""
    client = _client()
    await _setup(hass, client)
    cache = dict(hass.data[DOMAIN][ENTRY_ID][COORDINATOR].data)
    cache["update_time"] = time.time() - 7200
    assert await hass.config_entries.async_unload(ENTRY_ID)
    await hass.async_block_till_done()

    client.get_system_info.side_effect = PfSenseConnectionError("Connection refused")
    entry = hass.config_entries.async_get_entry(ENTRY_ID)
    with _patched(client, cache):
        assert await hass.config_entries.async_setup(ENTRY_ID)
        await hass.async_block_till_done()
    assert entry.state is ConfigEntryState.LOADED
    assert hass.states.get(STATUS).state == "unreachable"
    assert hass.states.get(STATUS).attributes["using_cache"] is True


async def test_pfrest_eol_warning_when_nexus_runs(hass: HomeAssistant) -> None:
    """A pfrest entry on a box running Nexus gets the end-of-life warning."""
    client = _client()
    client.get_services.return_value = [
        {"name": "unbound", "status": True},
        {"name": "pfnet-controller", "status": True},
    ]
    await _setup(hass, client)
    issue = _issue(hass, "pfrest_eol")
    assert issue is not None
    assert issue.severity is ir.IssueSeverity.WARNING


async def test_unload_clears_issues(hass: HomeAssistant) -> None:
    """Unloading the entry removes its repair issues."""
    client = _client()
    client.get_services.side_effect = PfSensePrivilegeError("forbidden")
    await _setup(hass, client)
    assert _issue(hass, "privilege_missing") is not None
    assert await hass.config_entries.async_unload(ENTRY_ID)
    await hass.async_block_till_done()
    assert _issue(hass, "privilege_missing") is None


async def test_diagnostics_are_redacted(hass: HomeAssistant) -> None:
    """Diagnostics carry health, not credentials, URLs or addresses."""
    client = _client()
    client.get_dhcp_leases.side_effect = PfSenseConnectionError(
        "Cannot connect to host 192.168.1.1:8444 ssl:default"
    )
    entry = await _setup(hass, client)
    diag = await async_get_config_entry_diagnostics(hass, entry)

    text = str(diag)
    assert "secret-key" not in text
    assert "192.168.1.1" not in text
    assert diag["entry"]["data"][CONF_API_KEY] == "**REDACTED**"
    assert diag["health"]["failing_checks"] == ["dhcp"]
    assert "<ip>" in diag["health"]["checks"]["dhcp"]["message"]
    assert diag["firewall"]["version"] == "26.07-RELEASE"
    assert diag["counts"]["services"] == 1


async def test_health_tracker_is_shared_in_hass_data(hass: HomeAssistant) -> None:
    """Platforms and diagnostics find the tracker under HEALTH."""
    await _setup(hass, _client())
    assert isinstance(hass.data[DOMAIN][ENTRY_ID][HEALTH], HealthTracker)
