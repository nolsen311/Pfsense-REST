"""Setup / unload / migration tests."""

from unittest.mock import AsyncMock, patch

import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.pfsense import async_setup_entry, async_unload_entry
from custom_components.pfsense.const import CONF_API_KEY, DOMAIN
from homeassistant.const import CONF_URL, CONF_VERIFY_SSL
from homeassistant.core import HomeAssistant


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations):
    yield


def _full_client_mock():
    client = AsyncMock()
    client.get_system_info.return_value = {
        "hostname": "router",
        "domain": "local",
        "netgate_device_id": "abc",
        "serial": "1",
        "platform": "Netgate",
    }
    client.get_host_firmware_version.return_value = {
        "platform": "Netgate",
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
    client.get_carp_status.return_value = False
    client.get_dhcp_leases.return_value = []
    client.get_dns_servers.return_value = []
    client.get_filter_rules.return_value = []
    client.get_nat_port_forward_rules.return_value = []
    client.get_nat_outbound_rules.return_value = []
    client.get_arp_table.return_value = []
    return client


@pytest.mark.asyncio
async def test_setup_and_unload_entry(hass: HomeAssistant):
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=3,
        data={
            CONF_URL: "https://192.168.1.1:8444",
            CONF_API_KEY: "k",
            CONF_VERIFY_SSL: False,
        },
        options={"device_tracker_enabled": False},
        entry_id="test_pfsense",
    )
    entry.add_to_hass(hass)

    with (
        patch(
            "custom_components.pfsense.pfSenseClient",
            return_value=_full_client_mock(),
        ),
        patch("custom_components.pfsense.async_load_cache", return_value=None),
        patch("custom_components.pfsense.async_save_cache"),
        patch(
            "homeassistant.config_entries.ConfigEntries.async_forward_entry_setups",
            return_value=True,
        ) as mock_forward,
    ):
        assert await async_setup_entry(hass, entry) is True
        assert mock_forward.called
        assert DOMAIN in hass.data

    with patch(
        "homeassistant.config_entries.ConfigEntries.async_unload_platforms",
        return_value=True,
    ) as mock_unload:
        assert await async_unload_entry(hass, entry) is True
        assert mock_unload.called
        assert entry.entry_id not in hass.data.get(DOMAIN, {})


@pytest.mark.asyncio
async def test_migrate_v2_password_entry_requires_reauth(hass: HomeAssistant):
    """A v2 (username/password) entry is stripped and pushed to reauth."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=2,
        data={
            CONF_URL: "https://192.168.1.1",
            "username": "admin",
            "password": "secret",
            CONF_VERIFY_SSL: True,
        },
        entry_id="legacy",
    )
    entry.add_to_hass(hass)

    assert await hass.config_entries.async_setup(entry.entry_id) is False
    await hass.async_block_till_done()

    assert entry.version == 3
    assert "password" not in entry.data
    assert "username" not in entry.data
    assert CONF_API_KEY not in entry.data
    flows = hass.config_entries.flow.async_progress()
    assert any(f["context"]["source"] == "reauth" for f in flows)
