"""Setup / unload / migration tests."""

from unittest.mock import AsyncMock, patch

import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.pfsense.const import (
    AUTH_METHOD_API_KEY,
    CONF_API_KEY,
    CONF_AUTH_METHOD,
    DOMAIN,
)
from homeassistant.components.update import UpdateEntityFeature
from homeassistant.config_entries import ConfigEntryState
from homeassistant.const import CONF_URL, CONF_VERIFY_SSL
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations):
    """Test helper."""
    return


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
    client.get_firmware_update_info.return_value = None
    client.get_installed_packages.return_value = []
    client.get_ntp_status.return_value = {
        "enabled": True,
        "synchronized": True,
        "peer": None,
        "offset_ms": 1.0,
        "stratum": 2,
        "peers": [],
    }
    client.get_state_table.return_value = {
        "current": 100,
        "limit": 1000,
        "used_percent": 10.0,
    }
    client.get_notices.return_value = {"count": 0, "latest": []}
    client.get_arp_table.return_value = []
    return client


@pytest.mark.asyncio
async def test_setup_and_unload_entry(hass: HomeAssistant):
    """Test setup and unload entry."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=3,
        title="router.local",
        unique_id="abc",
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
            "custom_components.pfsense.client_from_config",
            return_value=_full_client_mock(),
        ),
        patch("custom_components.pfsense.async_load_cache", return_value=None),
        patch("custom_components.pfsense.async_save_cache"),
    ):
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()

    assert entry.state is ConfigEntryState.LOADED
    assert entry.entry_id in hass.data[DOMAIN]

    assert await hass.config_entries.async_unload(entry.entry_id)
    await hass.async_block_till_done()

    assert entry.state is ConfigEntryState.NOT_LOADED
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

    assert entry.version == 5
    assert entry.data[CONF_AUTH_METHOD] == AUTH_METHOD_API_KEY
    assert "password" not in entry.data
    assert "username" not in entry.data
    assert CONF_API_KEY not in entry.data
    flows = hass.config_entries.flow.async_progress()
    assert any(f["context"]["source"] == "reauth" for f in flows)


@pytest.mark.asyncio
async def test_migrate_v3_stamps_auth_method(hass: HomeAssistant):
    """A v3 (api-key) entry gains auth_method=api_key and becomes v4."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=3,
        title="router.local",
        unique_id="abc",
        data={
            CONF_URL: "https://192.168.1.1:8444",
            CONF_API_KEY: "k",
            CONF_VERIFY_SSL: False,
        },
        options={"device_tracker_enabled": False},
        entry_id="v3_entry",
    )
    entry.add_to_hass(hass)

    with (
        patch(
            "custom_components.pfsense.client_from_config",
            return_value=_full_client_mock(),
        ),
        patch("custom_components.pfsense.async_load_cache", return_value=None),
        patch("custom_components.pfsense.async_save_cache"),
    ):
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()

    assert entry.version == 5
    assert entry.data[CONF_AUTH_METHOD] == AUTH_METHOD_API_KEY
    assert entry.data[CONF_API_KEY] == "k"


@pytest.mark.asyncio
async def test_migrate_v4_stamps_backend(hass: HomeAssistant):
    """A v4 entry gains backend=pfrest and becomes v5; nothing else changes."""
    data = {
        CONF_URL: "https://192.168.1.1:8444",
        CONF_API_KEY: "k",
        CONF_VERIFY_SSL: False,
        CONF_AUTH_METHOD: AUTH_METHOD_API_KEY,
    }
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=4,
        title="router.local",
        unique_id="abc",
        data=data,
        options={"device_tracker_enabled": False},
        entry_id="v4_entry",
    )
    entry.add_to_hass(hass)

    with (
        patch(
            "custom_components.pfsense.client_from_config",
            return_value=_full_client_mock(),
        ),
        patch("custom_components.pfsense.async_load_cache", return_value=None),
        patch("custom_components.pfsense.async_save_cache"),
    ):
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()

    assert entry.version == 5
    assert entry.data == {**data, "backend": "pfrest"}


def _netgate_entry(options: dict | None = None) -> MockConfigEntry:
    return MockConfigEntry(
        domain=DOMAIN,
        version=5,
        title="router.local",
        unique_id="abc",
        data={
            CONF_URL: "https://192.168.1.1:8443",
            "backend": "netgate",
            "auth_method": "netgate",
            "username": "u",
            "password": "p",
            CONF_VERIFY_SSL: False,
        },
        options={"device_tracker_enabled": False, **(options or {})},
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


UPDATE_ENTITY = "update.router_local_firmware_updates_available"
_UPDATE_INFO = {"base": {"installed_version": "26.07", "version": "26.10"}}


@pytest.mark.asyncio
async def test_install_is_opt_in(hass: HomeAssistant):
    """Without the option there is no Install feature and no warning."""
    client = _full_client_mock()
    client.get_firmware_update_info.return_value = _UPDATE_INFO
    entry = _netgate_entry()
    await _setup(hass, entry, client)
    state = hass.states.get(UPDATE_ENTITY)
    assert not state.attributes["supported_features"] & UpdateEntityFeature.INSTALL
    assert state.attributes["release_summary"] is None
    with pytest.raises(HomeAssistantError):
        await hass.services.async_call(
            "update", "install", {"entity_id": UPDATE_ENTITY}, blocking=True
        )
    client.start_firmware_update.assert_not_called()
    assert await hass.config_entries.async_unload(entry.entry_id)


@pytest.mark.asyncio
async def test_install_when_enabled_warns_and_tracks_progress(hass: HomeAssistant):
    """Opted in: warning shown, install starts, in progress until the version moves."""
    client = _full_client_mock()
    client.get_firmware_update_info.return_value = _UPDATE_INFO
    entry = _netgate_entry({"firmware_install_unverified": True})
    await _setup(hass, entry, client)

    state = hass.states.get(UPDATE_ENTITY)
    assert state.attributes["supported_features"] & UpdateEntityFeature.INSTALL
    assert "not been verified" in state.attributes["release_summary"]

    await hass.services.async_call(
        "update", "install", {"entity_id": UPDATE_ENTITY}, blocking=True
    )
    client.start_firmware_update.assert_awaited_once()
    assert hass.states.get(UPDATE_ENTITY).attributes["in_progress"] is True

    client.get_firmware_update_info.return_value = {
        "base": {"installed_version": "26.10", "version": "26.10"}
    }
    coordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    await coordinator.async_refresh()
    await hass.async_block_till_done()
    state = hass.states.get(UPDATE_ENTITY)
    assert state.attributes["in_progress"] is False
    assert state.attributes["installed_version"] == "26.10"
    assert await hass.config_entries.async_unload(entry.entry_id)


@pytest.mark.asyncio
async def test_install_option_ignored_for_pfrest(hass: HomeAssistant):
    """The option never adds Install to a pfrest entry."""
    client = _full_client_mock()
    client.get_firmware_update_info.return_value = _UPDATE_INFO
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=5,
        title="router.local",
        unique_id="abc",
        data={
            CONF_URL: "https://192.168.1.1:8444",
            CONF_API_KEY: "k",
            "backend": "pfrest",
            "auth_method": "api_key",
        },
        options={"device_tracker_enabled": False, "firmware_install_unverified": True},
    )
    await _setup(hass, entry, client)
    state = hass.states.get(UPDATE_ENTITY)
    assert not state.attributes["supported_features"] & UpdateEntityFeature.INSTALL
    assert await hass.config_entries.async_unload(entry.entry_id)


@pytest.mark.asyncio
async def test_update_entity_shows_base_versions(hass: HomeAssistant):
    """When the backend reports versions, the update entity shows them."""
    client = _full_client_mock()
    client.get_firmware_update_info.return_value = {
        "base": {
            "installed_version": "26.07",
            "version": "26.10",
            "status_message": "Update available.",
        }
    }
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=5,
        title="router.local",
        unique_id="abc",
        data={
            CONF_URL: "https://192.168.1.1:8443",
            "backend": "netgate",
            "auth_method": "netgate",
            "username": "u",
            "password": "p",
            CONF_VERIFY_SSL: False,
        },
        options={"device_tracker_enabled": False},
    )
    entry.add_to_hass(hass)
    with (
        patch("custom_components.pfsense.client_from_config", return_value=client),
        patch("custom_components.pfsense.async_load_cache", return_value=None),
        patch("custom_components.pfsense.async_save_cache"),
    ):
        assert await hass.config_entries.async_setup(entry.entry_id)
        await hass.async_block_till_done()

    state = hass.states.get("update.router_local_firmware_updates_available")
    assert state is not None
    assert state.state == "on"
    assert state.attributes["installed_version"] == "26.07"
    assert state.attributes["latest_version"] == "26.10"
    assert state.attributes["pfsense_base_status_message"] == "Update available."

    assert await hass.config_entries.async_unload(entry.entry_id)
    await hass.async_block_till_done()


PKG_ENTITY = "update.router_local_package_system_patches"


@pytest.mark.asyncio
async def test_package_update_entity_installs(hass: HomeAssistant):
    """A package with a newer catalog version can be installed and tracked."""
    client = _full_client_mock()
    client.get_installed_packages.return_value = [
        {
            "name": "System_Patches",
            "package": "pfSense-pkg-System_Patches",
            "installed_version": "2.3.5_1",
            "latest_version": "2.3.6",
            "update_available": True,
        }
    ]
    entry = _netgate_entry()
    await _setup(hass, entry, client)

    state = hass.states.get(PKG_ENTITY)
    assert state.state == "on"
    assert state.attributes["latest_version"] == "2.3.6"
    assert state.attributes["supported_features"] & UpdateEntityFeature.INSTALL

    await hass.services.async_call(
        "update", "install", {"entity_id": PKG_ENTITY}, blocking=True
    )
    client.install_package_update.assert_awaited_once_with("System_Patches")
    assert hass.states.get(PKG_ENTITY).attributes["in_progress"] is True

    client.get_installed_packages.return_value = [
        {
            "name": "System_Patches",
            "package": "pfSense-pkg-System_Patches",
            "installed_version": "2.3.6",
            "latest_version": "2.3.6",
            "update_available": False,
        }
    ]
    await hass.data[DOMAIN][entry.entry_id]["coordinator"].async_refresh()
    await hass.async_block_till_done()
    state = hass.states.get(PKG_ENTITY)
    assert (state.state, state.attributes["in_progress"]) == ("off", False)
    assert await hass.config_entries.async_unload(entry.entry_id)


@pytest.mark.asyncio
async def test_package_entity_has_no_install_on_pfrest(hass: HomeAssistant):
    """Pfrest entries never get Install on package entities."""
    client = _full_client_mock()
    client.get_installed_packages.return_value = [
        {"name": "acme", "installed_version": "1", "latest_version": "2"}
    ]
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=5,
        title="router.local",
        unique_id="abc",
        data={
            CONF_URL: "https://192.168.1.1:8444",
            CONF_API_KEY: "k",
            "backend": "pfrest",
            "auth_method": "api_key",
        },
        options={"device_tracker_enabled": False},
    )
    await _setup(hass, entry, client)
    state = hass.states.get("update.router_local_package_acme")
    assert not state.attributes["supported_features"] & UpdateEntityFeature.INSTALL
    assert await hass.config_entries.async_unload(entry.entry_id)


@pytest.mark.asyncio
async def test_ntp_entities(hass: HomeAssistant):
    """NTP sync binary sensor plus offset (with peer attributes) and stratum."""
    client = _full_client_mock()
    peer = {
        "server": "192.0.2.20",
        "status": "Active Peer",
        "refid": "17.253.4.37",
        "stratum": 2,
        "offset_ms": 3.704,
        "delay_ms": 29.716,
        "jitter_ms": 1.009,
        "reach": "377",
    }
    client.get_ntp_status.return_value = {
        "enabled": True,
        "synchronized": True,
        "peer": peer,
        "offset_ms": 3.704,
        "stratum": 2,
        "peers": [peer],
    }
    entry = _netgate_entry()
    await _setup(hass, entry, client)
    synced = hass.states.get("binary_sensor.router_local_ntp_synchronized")
    assert synced.state == "on"
    assert synced.attributes["peer"] == "192.0.2.20"
    offset = hass.states.get("sensor.router_local_ntp_offset")
    assert offset.state == "3.704"
    assert offset.attributes["peer_server"] == "192.0.2.20"
    assert offset.attributes["jitter_ms"] == 1.009
    assert await hass.config_entries.async_unload(entry.entry_id)


@pytest.mark.asyncio
async def test_ntp_unavailable_when_unsupported(hass: HomeAssistant):
    """Without NTP status (pfrest), the sync sensor is unavailable, not off."""
    from custom_components.pfsense.pypfsense import (  # noqa: PLC0415
        PfSenseUnsupportedError,
    )

    client = _full_client_mock()
    client.get_ntp_status.side_effect = PfSenseUnsupportedError("pfrest")
    entry = _netgate_entry()
    await _setup(hass, entry, client)
    synced = hass.states.get("binary_sensor.router_local_ntp_synchronized")
    assert synced.state == "unavailable"


async def test_state_table_sensors(hass: HomeAssistant):
    """Entries and usage sensors, with the dataset extras as attributes."""
    client = _full_client_mock()
    client.get_state_table.return_value = {
        "current": 2126,
        "limit": 805000,
        "used_percent": 0.26,
        "nat_states": 373.6,
        "source_ips": None,
        "destination_ips": 200.5,
    }
    entry = _netgate_entry()
    await _setup(hass, entry, client)
    entries = hass.states.get("sensor.router_local_state_table_entries")
    assert entries.state == "2126"
    assert entries.attributes["nat_states"] == 373.6
    assert "source_ips" not in entries.attributes
    assert hass.states.get("sensor.router_local_state_table_usage").state == "0.26"
    assert await hass.config_entries.async_unload(entry.entry_id)
