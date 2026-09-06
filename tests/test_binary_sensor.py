"""Binary sensor tests (integration boots and CARP state is reflected)."""

from unittest.mock import AsyncMock, patch

import pytest
from homeassistant.const import CONF_URL, CONF_VERIFY_SSL
from homeassistant.core import HomeAssistant
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.pfsense.const import CONF_API_KEY, COORDINATOR, DOMAIN


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations):
    yield


@pytest.fixture
def mock_pfsense_client():
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
        patch("custom_components.pfsense.pfSenseClient", return_value=client),
        patch("custom_components.pfsense.async_load_cache", return_value=None),
        patch("custom_components.pfsense.async_save_cache"),
    ):
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()


@pytest.mark.asyncio
async def test_carp_sensor_on(hass: HomeAssistant, mock_pfsense_client):
    mock_pfsense_client.get_carp_status.return_value = True
    await _setup(hass, _entry("carp_on"), mock_pfsense_client)

    coordinator = hass.data[DOMAIN]["carp_on"][COORDINATOR]
    assert coordinator.data["carp_status"] is True
    # Notices have no REST endpoint; that binary sensor no longer exists.
    assert hass.states.get("binary_sensor.router_local_pending_notices_present") is None
    assert hass.states.get("binary_sensor.router_local_carp_status") is not None


@pytest.mark.asyncio
async def test_carp_sensor_off(hass: HomeAssistant, mock_pfsense_client):
    mock_pfsense_client.get_carp_status.return_value = False
    await _setup(hass, _entry("carp_off"), mock_pfsense_client)

    coordinator = hass.data[DOMAIN]["carp_off"][COORDINATOR]
    assert coordinator.data["carp_status"] is False
