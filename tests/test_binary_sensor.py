"""Binary sensor tests (integration boots and CARP state is reflected)."""

from unittest.mock import AsyncMock, patch

import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.pfsense.const import CONF_API_KEY, COORDINATOR, DOMAIN
from homeassistant.const import CONF_URL, CONF_VERIFY_SSL
from homeassistant.core import HomeAssistant


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations):
    """Test helper."""
    return


@pytest.fixture
def mock_pfsense_client():
    """Test helper."""
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
        "interfaces": {},
        "gateways": {},
        "gateways_detail": {},
        "openvpn": {"servers": {}},
        "system": {"load_average": {}},
        "cpu": {},
        "memory": {},
        "mbuf": {},
        "filesystems": [],
        "wan_ip": "1.2.3.4",
    }
    client.get_services.return_value = []
    client.get_carp_interfaces.return_value = []
    client.get_dhcp_leases.return_value = []
    client.get_dns_servers.return_value = []
    client.get_filter_rules.return_value = []
    client.get_nat_port_forward_rules.return_value = []
    client.get_nat_outbound_rules.return_value = []
    client.get_firmware_update_info.return_value = None
    client.get_installed_packages.return_value = []
    client.get_dyndns.return_value = []
    client.get_ntp_status.return_value = {
        "enabled": True,
        "synchronized": True,
        "peer": None,
        "offset_ms": 1.0,
        "stratum": 2,
        "peers": [],
    }
    client.get_certificates.return_value = []
    client.get_state_table.return_value = {
        "current": 100,
        "limit": 1000,
        "used_percent": 10.0,
    }
    client.get_notices.return_value = {"count": 0, "latest": []}
    return client


def _entry(entry_id):
    return MockConfigEntry(
        domain=DOMAIN,
        version=3,
        title="router.local",
        unique_id="mock_id_12345",
        data={
            CONF_URL: "https://192.168.1.1:8444",
            CONF_API_KEY: "k",
            CONF_VERIFY_SSL: False,
        },
        options={"device_tracker_enabled": False},
        entry_id=entry_id,
    )


async def _setup(hass, entry, client):
    entry.add_to_hass(hass)
    with (
        patch("custom_components.pfsense.client_from_config", return_value=client),
        patch("custom_components.pfsense.async_load_cache", return_value=None),
        patch("custom_components.pfsense.async_save_cache"),
    ):
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()


@pytest.mark.asyncio
async def test_carp_sensor_on(hass: HomeAssistant, mock_pfsense_client):
    """Test carp sensor on."""
    mock_pfsense_client.get_carp_status.return_value = True
    await _setup(hass, _entry("carp_on"), mock_pfsense_client)

    coordinator = hass.data[DOMAIN]["carp_on"][COORDINATOR]
    assert coordinator.data["carp_status"] is True
    # Notices are back (read through the shell), off with none pending.
    notices = hass.states.get("binary_sensor.router_local_pending_notices_present")
    assert notices.state == "off"
    assert hass.states.get("binary_sensor.router_local_carp_status") is not None


@pytest.mark.asyncio
async def test_carp_sensor_off(hass: HomeAssistant, mock_pfsense_client):
    """Test carp sensor off."""
    mock_pfsense_client.get_carp_status.return_value = False
    await _setup(hass, _entry("carp_off"), mock_pfsense_client)

    coordinator = hass.data[DOMAIN]["carp_off"][COORDINATOR]
    assert coordinator.data["carp_status"] is False


@pytest.mark.asyncio
async def test_pending_notices_sensor(hass: HomeAssistant, mock_pfsense_client):
    """Pending notices turn the sensor on, with the newest ones as attributes."""
    latest = [
        {"id": 1794900000, "category": "PHP errors", "priority": 1, "notice": "x"}
    ]
    mock_pfsense_client.get_notices.return_value = {"count": 27, "latest": latest}
    await _setup(hass, _entry("notices_on"), mock_pfsense_client)
    state = hass.states.get("binary_sensor.router_local_pending_notices_present")
    assert state.state == "on"
    assert state.attributes["pending_count"] == 27
    assert state.attributes["latest_notices"] == latest


@pytest.mark.asyncio
async def test_pending_notices_unavailable_without_shell(
    hass: HomeAssistant, mock_pfsense_client
):
    """When notices cannot be read, the sensor is unavailable, not 'off'."""
    from custom_components.pfsense.pypfsense import (  # noqa: PLC0415
        PfSenseUnsupportedError,
    )

    mock_pfsense_client.get_notices.side_effect = PfSenseUnsupportedError("no shell")
    await _setup(hass, _entry("notices_off"), mock_pfsense_client)
    state = hass.states.get("binary_sensor.router_local_pending_notices_present")
    assert state.state == "unavailable"
