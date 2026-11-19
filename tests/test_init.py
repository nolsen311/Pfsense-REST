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
from homeassistant.helpers import entity_registry as er


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
    client.get_dns_resolver_status.return_value = []
    client.get_pf_tables.return_value = []
    client.get_schedules.return_value = {"timezone": None, "schedules": []}
    client.get_boot_environments.return_value = []
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
async def test_dyndns_sensor(hass: HomeAssistant):
    """A dynamic DNS entry shows its registered address and last update."""
    client = _full_client_mock()
    client.get_dyndns.return_value = [
        {
            "id": "0",
            "type": "cloudflare",
            "interface": "wan",
            "hostname": "@.example.com",
            "description": None,
            "enabled": True,
            "ip": "203.0.113.7",
            "ipv6": "2001:db8::1",
            "last_update": 1793001661,
            "cache_readable": True,
        }
    ]
    entry = _netgate_entry()
    await _setup(hass, entry, client)
    state = hass.states.get("sensor.router_local_dynamic_dns_example_com")
    assert state.state == "203.0.113.7"
    assert state.attributes["provider"] == "cloudflare"
    assert state.attributes["ipv6"] == "2001:db8::1"
    assert state.attributes["last_update"].startswith("2026-")
    assert "password" not in state.attributes


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


async def test_certificate_sensor_and_repair(hass: HomeAssistant):
    """A cert expiring soon gets a timestamp sensor and a repair."""
    from datetime import timedelta  # noqa: PLC0415

    from homeassistant.helpers import issue_registry as ir  # noqa: PLC0415
    from homeassistant.util import dt as dt_util  # noqa: PLC0415

    soon = (dt_util.utcnow() + timedelta(days=5)).replace(microsecond=0)
    client = _full_client_mock()
    client.get_certificates.return_value = [
        {
            "refid": "abc123",
            "name": "GUI",
            "type": "server",
            "in_use": "webConfigurator",
            "starts": None,
            "expires": soon.isoformat(),
            "issuer": "self-signed",
            "can_renew": True,
        }
    ]
    entry = _netgate_entry()
    await _setup(hass, entry, client)
    state = hass.states.get("sensor.router_local_certificate_gui_expires")
    assert dt_util.parse_datetime(state.state) == soon
    assert state.attributes["days_left"] in (4, 5)
    assert state.attributes["in_use"] == "webConfigurator"
    issue = ir.async_get(hass).async_get_issue(
        "pfsense", f"certificate_expiring_{entry.entry_id}"
    )
    assert issue is not None
    assert "GUI (in" in issue.translation_placeholders["certificates"]


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


_PKG_WITH_UPDATE = [
    {
        "name": "System_Patches",
        "package": "pfSense-pkg-System_Patches",
        "installed_version": "2.3.5_1",
        "latest_version": "2.3.6",
        "update_available": True,
    }
]


@pytest.mark.asyncio
async def test_install_backs_up_first(hass: HomeAssistant):
    """Back up first: a boot environment snapshot is taken before installing."""
    from unittest.mock import call  # noqa: PLC0415

    client = _full_client_mock()
    client.get_installed_packages.return_value = _PKG_WITH_UPDATE
    order = AsyncMock()
    order.snapshot.return_value = "quick-20261117165509"
    client.create_boot_environment = order.snapshot
    client.install_package_update = order.install
    entry = _netgate_entry()
    await _setup(hass, entry, client)
    assert (
        hass.states.get(PKG_ENTITY).attributes["supported_features"]
        & UpdateEntityFeature.BACKUP
    )
    await hass.services.async_call(
        "update", "install", {"entity_id": PKG_ENTITY, "backup": True}, blocking=True
    )
    assert order.mock_calls == [call.snapshot(), call.install("System_Patches")]
    assert await hass.config_entries.async_unload(entry.entry_id)


@pytest.mark.asyncio
async def test_failed_snapshot_blocks_install(hass: HomeAssistant):
    """If the boot environment can't be created, nothing is installed."""
    from custom_components.pfsense.pypfsense import PfSenseAPIError  # noqa: PLC0415
    from homeassistant.exceptions import HomeAssistantError  # noqa: PLC0415

    client = _full_client_mock()
    client.get_installed_packages.return_value = _PKG_WITH_UPDATE
    client.create_boot_environment.side_effect = PfSenseAPIError(500, "", "zfs full")
    entry = _netgate_entry()
    await _setup(hass, entry, client)
    with pytest.raises(HomeAssistantError, match="nothing was installed"):
        await hass.services.async_call(
            "update",
            "install",
            {"entity_id": PKG_ENTITY, "backup": True},
            blocking=True,
        )
    client.install_package_update.assert_not_awaited()
    # Without backup, no snapshot is taken.
    client.create_boot_environment.reset_mock()
    await hass.services.async_call(
        "update", "install", {"entity_id": PKG_ENTITY}, blocking=True
    )
    client.create_boot_environment.assert_not_awaited()
    assert await hass.config_entries.async_unload(entry.entry_id)


@pytest.mark.asyncio
async def test_boot_environment_sensor(hass: HomeAssistant):
    """The active environment is the state; all of them are attributes."""
    client = _full_client_mock()
    client.get_boot_environments.return_value = [
        {
            "name": "new",
            "version": "26.07",
            "active": True,
            "next_boot": True,
            "created": "2026-08-15T07:20:06+00:00",
            "used_bytes": 2296274944,
            "protected": False,
        },
        {
            "name": "old",
            "version": "26.03.1",
            "active": False,
            "next_boot": False,
            "created": "2026-06-03T14:49:55+00:00",
            "used_bytes": 1003520,
            "protected": True,
        },
    ]
    entry = _netgate_entry()
    await _setup(hass, entry, client)
    state = hass.states.get("sensor.router_local_boot_environment")
    assert state.state == "new"
    assert state.attributes["version"] == "26.07"
    assert state.attributes["next_boot"] == "new"
    assert state.attributes["count"] == 2
    assert state.attributes["environments"][1]["protected"] is True
    assert await hass.config_entries.async_unload(entry.entry_id)


@pytest.mark.asyncio
async def test_safe_upgrade_install_routes_through_manager(hass: HomeAssistant):
    """With safe upgrade on, Install starts the sequence, not a bare upgrade."""
    client = _full_client_mock()
    client.get_firmware_update_info.return_value = _UPDATE_INFO
    entry = _netgate_entry(
        {
            "firmware_install_unverified": True,
            "firmware_safe_upgrade": True,
            "firmware_backup_password": "pw",
        }
    )
    await _setup(hass, entry, client)
    manager = hass.data[DOMAIN][entry.entry_id]["safe_upgrade"]
    with patch.object(manager, "async_start", AsyncMock()) as start:
        await hass.services.async_call(
            "update", "install", {"entity_id": UPDATE_ENTITY}, blocking=True
        )
    start.assert_awaited_once_with("26.07")
    client.start_firmware_update.assert_not_awaited()
    assert (
        "Safe upgrade is on"
        in hass.states.get(UPDATE_ENTITY).attributes["release_summary"]
    )
    assert await hass.config_entries.async_unload(entry.entry_id)


@pytest.mark.asyncio
async def test_diagnostics_redact_backup_password(hass: HomeAssistant):
    """The config backup password never appears in diagnostics."""
    from custom_components.pfsense.diagnostics import (  # noqa: PLC0415
        async_get_config_entry_diagnostics,
    )

    client = _full_client_mock()
    entry = _netgate_entry({"firmware_backup_password": "s3cret"})
    await _setup(hass, entry, client)
    diag = await async_get_config_entry_diagnostics(hass, entry)
    assert diag["entry"]["options"]["firmware_backup_password"] == "**REDACTED**"
    assert "s3cret" not in repr(diag)
    assert await hass.config_entries.async_unload(entry.entry_id)


@pytest.mark.asyncio
async def test_schedule_and_resolver_entities(hass: HomeAssistant, freezer):
    """Schedules are evaluated in the firewall's timezone; RTT per upstream."""
    # 20:30 in Los Angeles = 04:30 UTC next day.
    freezer.move_to("2026-11-18T04:30:00+00:00")
    client = _full_client_mock()
    client.get_schedules.return_value = {
        "timezone": "America/Los_Angeles",
        "schedules": [
            {
                "name": "6a_10p_Daylight",
                "description": None,
                "ranges": [
                    {
                        "weekdays": [1, 2, 3, 4, 5, 6, 7],
                        "dates": None,
                        "start": 360,
                        "end": 1320,
                        "hours": "06:00-22:00",
                        "description": "6a to 10p",
                    }
                ],
            },
            {
                "name": "Overnight_22_6",
                "description": None,
                "ranges": [
                    {
                        "weekdays": [1, 2, 3, 4, 5, 6, 7],
                        "dates": None,
                        "start": 1320,
                        "end": 1439,
                        "hours": "22:00-23:59",
                        "description": None,
                    }
                ],
            },
        ],
    }
    client.get_dns_resolver_status.return_value = [
        {
            "server": "1.1.1.1@853",
            "address": "1.1.1.1",
            "port": 853,
            "zone": ".",
            "rtt_ms": 127.0,
            "ping_ms": 35.0,
            "variance_ms": 23.0,
            "rto_ms": 127.0,
            "timeouts": 0,
            "timeouts_a": 0,
            "timeouts_aaaa": 0,
            "timeouts_other": 0,
            "lame": 0,
            "expired": False,
        }
    ]
    entry = _netgate_entry()
    await _setup(hass, entry, client)
    day = hass.states.get("binary_sensor.router_local_schedule_6a_10p_daylight")
    assert day.state == "on"  # 20:30 local, although it is 04:30 UTC
    assert day.attributes["timezone"] == "America/Los_Angeles"
    assert day.attributes["ranges"][0] == {
        "days": "Mon,Tue,Wed,Thu,Fri,Sat,Sun",
        "hours": "06:00-22:00",
        "description": "6a to 10p",
    }
    assert (
        hass.states.get("binary_sensor.router_local_schedule_overnight_22_6").state
        == "off"
    )
    rtt = hass.states.get("sensor.router_local_dns_resolver_1_1_1_1_rtt")
    assert rtt.state == "127.0"
    assert rtt.attributes["port"] == 853 and rtt.attributes["ping_ms"] == 35.0
    assert await hass.config_entries.async_unload(entry.entry_id)


@pytest.mark.asyncio
async def test_pf_table_sensors(hass: HomeAssistant):
    """Runtime tables are enabled; alias tables start disabled."""
    client = _full_client_mock()
    client.get_pf_tables.return_value = [
        {
            "name": "sshguard",
            "count": 1,
            "entries": ["203.0.113.7"],
            "truncated": False,
            "last_update": None,
            "action": "empty",
        },
        {
            "name": "trustedMgmt",
            "count": 3,
            "entries": ["10.0.0.1"],
            "truncated": False,
            "last_update": None,
            "action": "empty",
        },
    ]
    entry = _netgate_entry()
    await _setup(hass, entry, client)
    guard = hass.states.get("sensor.router_local_pf_table_sshguard")
    assert guard.state == "1"
    assert guard.attributes["entries"] == ["203.0.113.7"]
    assert hass.states.get("sensor.router_local_pf_table_trustedmgmt") is None
    reg = er.async_get(hass).async_get("sensor.router_local_pf_table_trustedmgmt")
    assert reg is not None and reg.disabled_by is er.RegistryEntryDisabler.INTEGRATION
    assert await hass.config_entries.async_unload(entry.entry_id)
