"""Config flow tests for the REST API v2 multi-method auth model."""

from unittest.mock import AsyncMock, patch

import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.pfsense.const import (
    AUTH_METHOD_API_KEY,
    AUTH_METHOD_BASIC,
    AUTH_METHOD_JWT,
    AUTH_METHOD_NETGATE,
    CONF_API_KEY,
    CONF_AUTH_METHOD,
    CONF_DEVICE_TRACKER_ENABLED,
    CONF_DEVICES,
    DOMAIN,
)
from custom_components.pfsense.pypfsense import (
    BACKEND_NETGATE,
    BACKEND_PFREST,
    CONF_BACKEND,
    PfSenseAuthError,
)
from homeassistant.const import CONF_PASSWORD, CONF_URL, CONF_USERNAME, CONF_VERIFY_SSL
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType


def _client_mock(**overrides):
    client = AsyncMock()
    client.get_system_info.return_value = {
        "hostname": "router",
        "domain": "local",
        "netgate_device_id": "mock_id_12345",
    }
    for key, value in overrides.items():
        getattr(client, key).return_value = value
    return client


def _patch_client(client):
    return patch(
        "custom_components.pfsense.config_flow.client_from_config",
        return_value=client,
    )


async def _menu_pick(hass, step):
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": "user"}
    )
    assert result["type"] == FlowResultType.MENU
    return await hass.config_entries.flow.async_configure(
        result["flow_id"], {"next_step_id": step}
    )


@pytest.mark.asyncio
async def test_form_api_key_success(hass: HomeAssistant):
    """The API-key path creates an entry stamped auth_method=api_key."""
    form = await _menu_pick(hass, AUTH_METHOD_API_KEY)
    assert form["step_id"] == AUTH_METHOD_API_KEY

    with (
        _patch_client(_client_mock()),
        patch("custom_components.pfsense.async_setup_entry", return_value=True),
    ):
        result = await hass.config_entries.flow.async_configure(
            form["flow_id"],
            {
                CONF_URL: "https://192.168.1.1:8444",
                CONF_API_KEY: "abc123",
                CONF_VERIFY_SSL: False,
            },
        )
    assert result["type"] == FlowResultType.CREATE_ENTRY
    assert result["title"] == "router.local"
    assert result["data"] == {
        CONF_URL: "https://192.168.1.1:8444",
        CONF_VERIFY_SSL: False,
        CONF_BACKEND: BACKEND_PFREST,
        CONF_AUTH_METHOD: AUTH_METHOD_API_KEY,
        CONF_API_KEY: "abc123",
    }


@pytest.mark.asyncio
async def test_form_basic_success(hass: HomeAssistant):
    """The username/password path stores auth_method=basic + credentials."""
    form = await _menu_pick(hass, AUTH_METHOD_BASIC)
    assert form["step_id"] == AUTH_METHOD_BASIC

    with (
        _patch_client(_client_mock()),
        patch("custom_components.pfsense.async_setup_entry", return_value=True),
    ):
        result = await hass.config_entries.flow.async_configure(
            form["flow_id"],
            {
                CONF_URL: "https://192.168.1.1:8444",
                CONF_USERNAME: "admin",
                CONF_PASSWORD: "pfsense",
                CONF_VERIFY_SSL: False,
            },
        )
    assert result["type"] == FlowResultType.CREATE_ENTRY
    assert result["data"] == {
        CONF_URL: "https://192.168.1.1:8444",
        CONF_VERIFY_SSL: False,
        CONF_BACKEND: BACKEND_PFREST,
        CONF_AUTH_METHOD: AUTH_METHOD_BASIC,
        CONF_USERNAME: "admin",
        CONF_PASSWORD: "pfsense",
    }


@pytest.mark.asyncio
async def test_form_jwt_success(hass: HomeAssistant):
    """The JWT path stores auth_method=jwt + the credentials it mints from."""
    form = await _menu_pick(hass, AUTH_METHOD_JWT)
    assert form["step_id"] == AUTH_METHOD_JWT

    with (
        _patch_client(_client_mock()),
        patch("custom_components.pfsense.async_setup_entry", return_value=True),
    ):
        result = await hass.config_entries.flow.async_configure(
            form["flow_id"],
            {
                CONF_URL: "https://192.168.1.1:8444",
                CONF_USERNAME: "admin",
                CONF_PASSWORD: "pfsense",
            },
        )
    assert result["type"] == FlowResultType.CREATE_ENTRY
    assert result["data"][CONF_AUTH_METHOD] == AUTH_METHOD_JWT
    assert result["data"][CONF_USERNAME] == "admin"
    assert result["data"][CONF_PASSWORD] == "pfsense"


@pytest.mark.asyncio
async def test_form_invalid_auth(hass: HomeAssistant):
    """A rejected credential re-shows the form with an error."""
    form = await _menu_pick(hass, AUTH_METHOD_API_KEY)
    client = AsyncMock()
    client.get_system_info.side_effect = PfSenseAuthError("bad key")
    with _patch_client(client):
        result = await hass.config_entries.flow.async_configure(
            form["flow_id"],
            {CONF_URL: "https://192.168.1.1:8444", CONF_API_KEY: "nope"},
        )
    assert result["type"] == FlowResultType.FORM
    assert result["errors"]["base"] == "invalid_auth"


@pytest.mark.asyncio
async def test_reauth_flow_basic_entry(hass: HomeAssistant):
    """Reauth for a basic entry re-prompts for username + password."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=4,
        unique_id="mock_id_12345",
        data={
            CONF_URL: "https://192.168.1.1:8444",
            CONF_VERIFY_SSL: False,
            CONF_AUTH_METHOD: AUTH_METHOD_BASIC,
            CONF_USERNAME: "admin",
            CONF_PASSWORD: "old",
        },
    )
    entry.add_to_hass(hass)

    result = await entry.start_reauth_flow(hass)
    assert result["step_id"] == "reauth_confirm"

    with (
        _patch_client(_client_mock()),
        patch("custom_components.pfsense.async_setup_entry", return_value=True),
    ):
        result2 = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {CONF_USERNAME: "admin", CONF_PASSWORD: "new"},
        )
    assert result2["type"] == FlowResultType.ABORT
    assert result2["reason"] == "reauth_successful"
    assert entry.data[CONF_PASSWORD] == "new"
    assert entry.data[CONF_AUTH_METHOD] == AUTH_METHOD_BASIC


@pytest.mark.asyncio
async def test_options_flow(hass: HomeAssistant):
    """Test options flow."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=4,
        data={
            CONF_URL: "https://192.168.1.1:8444",
            CONF_AUTH_METHOD: AUTH_METHOD_API_KEY,
            CONF_API_KEY: "k",
            CONF_VERIFY_SSL: False,
        },
        options={CONF_DEVICES: []},
    )
    entry.add_to_hass(hass)

    client = _client_mock(
        get_arp_table=[
            {
                "mac_address": "11:22:33:44:55:66",
                "hostname": "Test-PC",
                "ip_address": "192.168.1.10",
            }
        ]
    )
    with _patch_client(client):
        result = await hass.config_entries.options.async_init(entry.entry_id)
        result2 = await hass.config_entries.options.async_configure(
            result["flow_id"], user_input={CONF_DEVICE_TRACKER_ENABLED: True}
        )
        assert result2["step_id"] == "device_tracker"
        result3 = await hass.config_entries.options.async_configure(
            result2["flow_id"], user_input={CONF_DEVICES: ["11:22:33:44:55:66"]}
        )
    assert result3["type"] == FlowResultType.CREATE_ENTRY
    assert entry.options[CONF_DEVICES] == ["11:22:33:44:55:66"]


@pytest.mark.asyncio
async def test_form_netgate_success(hass: HomeAssistant):
    """The Netgate API path stores backend=netgate and the login credentials."""
    form = await _menu_pick(hass, AUTH_METHOD_NETGATE)
    assert form["step_id"] == AUTH_METHOD_NETGATE
    assert form["description_placeholders"]["example_url"].endswith(":8443")

    with (
        _patch_client(_client_mock()) as factory,
        patch("custom_components.pfsense.async_setup_entry", return_value=True),
    ):
        result = await hass.config_entries.flow.async_configure(
            form["flow_id"],
            {
                CONF_URL: "https://192.168.1.1:8443/",
                CONF_USERNAME: "ha",
                CONF_PASSWORD: "pw",
                CONF_VERIFY_SSL: False,
            },
        )
    assert result["type"] == FlowResultType.CREATE_ENTRY
    assert result["result"].version == 5
    assert result["data"] == {
        CONF_URL: "https://192.168.1.1:8443",
        CONF_VERIFY_SSL: False,
        CONF_BACKEND: BACKEND_NETGATE,
        CONF_AUTH_METHOD: AUTH_METHOD_NETGATE,
        CONF_USERNAME: "ha",
        CONF_PASSWORD: "pw",
    }
    assert factory.call_args.args[2][CONF_BACKEND] == BACKEND_NETGATE


@pytest.mark.asyncio
async def test_form_netgate_invalid_auth(hass: HomeAssistant):
    """A rejected Netgate login shows invalid_auth on the same form."""
    form = await _menu_pick(hass, AUTH_METHOD_NETGATE)
    client = _client_mock()
    client.get_system_info.side_effect = PfSenseAuthError("invalid credentials")
    with _patch_client(client):
        result = await hass.config_entries.flow.async_configure(
            form["flow_id"],
            {
                CONF_URL: "https://192.168.1.1:8443",
                CONF_USERNAME: "ha",
                CONF_PASSWORD: "wrong",
            },
        )
    assert result["type"] == FlowResultType.FORM
    assert result["step_id"] == AUTH_METHOD_NETGATE
    assert result["errors"] == {"base": "invalid_auth"}


def _pfrest_entry(hass) -> MockConfigEntry:
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=5,
        unique_id="mock_id_12345",
        title="router.local",
        data={
            CONF_URL: "https://10.0.0.1:8444",
            CONF_VERIFY_SSL: False,
            CONF_BACKEND: BACKEND_PFREST,
            CONF_AUTH_METHOD: AUTH_METHOD_API_KEY,
            CONF_API_KEY: "old-key",
        },
    )
    entry.add_to_hass(hass)
    return entry


async def _reconfigure_pick(hass, entry, step):
    result = await entry.start_reconfigure_flow(hass)
    assert result["type"] == FlowResultType.MENU
    assert f"reconfigure_{AUTH_METHOD_NETGATE}" in result["menu_options"]
    return await hass.config_entries.flow.async_configure(
        result["flow_id"], {"next_step_id": step}
    )


@pytest.mark.asyncio
async def test_reconfigure_pfrest_to_netgate(hass: HomeAssistant):
    """A pfrest entry moves to Netgate in place: same entry, new data, reload."""
    entry = _pfrest_entry(hass)
    form = await _reconfigure_pick(hass, entry, f"reconfigure_{AUTH_METHOD_NETGATE}")
    assert form["type"] == FlowResultType.FORM
    # Host kept, port switched to Netgate's; verify_ssl carried over.
    schema = {str(k): k for k in form["data_schema"].schema}
    assert schema[CONF_URL].default() == "https://10.0.0.1:8443"
    assert schema[CONF_VERIFY_SSL].default() is False
    assert "name" not in schema

    with (
        _patch_client(_client_mock()),
        patch(
            "homeassistant.config_entries.ConfigEntries.async_reload",
            return_value=True,
        ) as reload,
    ):
        result = await hass.config_entries.flow.async_configure(
            form["flow_id"],
            {
                CONF_URL: "https://10.0.0.1:8443",
                CONF_USERNAME: "ha",
                CONF_PASSWORD: "pw",
                CONF_VERIFY_SSL: False,
            },
        )
    assert result["type"] == FlowResultType.ABORT
    assert result["reason"] == "reconfigure_successful"
    assert entry.data == {
        CONF_URL: "https://10.0.0.1:8443",
        CONF_VERIFY_SSL: False,
        CONF_BACKEND: BACKEND_NETGATE,
        CONF_AUTH_METHOD: AUTH_METHOD_NETGATE,
        CONF_USERNAME: "ha",
        CONF_PASSWORD: "pw",
    }  # the old API key is gone
    assert entry.unique_id == "mock_id_12345"
    assert len(hass.config_entries.async_entries(DOMAIN)) == 1
    reload.assert_called_once_with(entry.entry_id)


@pytest.mark.asyncio
async def test_reconfigure_rejects_a_different_firewall(hass: HomeAssistant):
    """Reconfigure cannot repoint an entry at another device."""
    entry = _pfrest_entry(hass)
    form = await _reconfigure_pick(hass, entry, f"reconfigure_{AUTH_METHOD_NETGATE}")
    other = _client_mock()
    other.get_system_info.return_value = {
        "hostname": "x",
        "domain": "y",
        "netgate_device_id": "someone_else",
    }
    with _patch_client(other):
        result = await hass.config_entries.flow.async_configure(
            form["flow_id"],
            {CONF_URL: "https://10.0.0.9:8443", CONF_USERNAME: "a", CONF_PASSWORD: "b"},
        )
    assert result["type"] == FlowResultType.ABORT
    assert result["reason"] == "wrong_device"
    assert entry.data[CONF_API_KEY] == "old-key"


@pytest.mark.asyncio
async def test_reconfigure_bad_credentials_shows_error(hass: HomeAssistant):
    """A failed check leaves the entry untouched and re-shows the form."""
    entry = _pfrest_entry(hass)
    form = await _reconfigure_pick(hass, entry, f"reconfigure_{AUTH_METHOD_NETGATE}")
    client = _client_mock()
    client.get_system_info.side_effect = PfSenseAuthError("nope")
    with _patch_client(client):
        result = await hass.config_entries.flow.async_configure(
            form["flow_id"],
            {CONF_URL: "https://10.0.0.1:8443", CONF_USERNAME: "a", CONF_PASSWORD: "b"},
        )
    assert result["type"] == FlowResultType.FORM
    assert result["step_id"] == f"reconfigure_{AUTH_METHOD_NETGATE}"
    assert result["errors"] == {"base": "invalid_auth"}
    assert entry.data[CONF_BACKEND] == BACKEND_PFREST


@pytest.mark.asyncio
async def test_reconfigure_same_backend_keeps_url_and_username(hass: HomeAssistant):
    """Staying on a backend pre-fills the current URL and username, no secrets."""
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=5,
        unique_id="mock_id_12345",
        data={
            CONF_URL: "https://10.0.0.1:8443",
            CONF_BACKEND: BACKEND_NETGATE,
            CONF_AUTH_METHOD: AUTH_METHOD_NETGATE,
            CONF_USERNAME: "ha",
            CONF_PASSWORD: "secret",
        },
    )
    entry.add_to_hass(hass)
    form = await _reconfigure_pick(hass, entry, f"reconfigure_{AUTH_METHOD_NETGATE}")
    schema = {str(k): k for k in form["data_schema"].schema}
    assert schema[CONF_URL].default() == "https://10.0.0.1:8443"
    assert schema[CONF_USERNAME].default() == "ha"
    assert schema[CONF_PASSWORD].default() == ""


@pytest.mark.asyncio
async def test_adding_same_firewall_twice_aborts(hass: HomeAssistant):
    """A second entry for one device aborts cleanly (not an 'unknown' error)."""
    _pfrest_entry(hass)
    form = await _menu_pick(hass, AUTH_METHOD_NETGATE)
    with _patch_client(_client_mock()):
        result = await hass.config_entries.flow.async_configure(
            form["flow_id"],
            {CONF_URL: "https://10.0.0.1:8443", CONF_USERNAME: "a", CONF_PASSWORD: "b"},
        )
    assert result["type"] == FlowResultType.ABORT
    assert result["reason"] == "already_configured"


@pytest.mark.asyncio
async def test_firmware_install_option_only_for_netgate(hass: HomeAssistant):
    """The unverified-install opt-in is offered on Netgate entries only."""
    pfrest = _pfrest_entry(hass)
    result = await hass.config_entries.options.async_init(pfrest.entry_id)
    assert "firmware_install_unverified" not in {
        str(k) for k in result["data_schema"].schema
    }
    netgate = MockConfigEntry(
        domain=DOMAIN,
        version=5,
        unique_id="other",
        data={CONF_URL: "https://10.0.0.2:8443", CONF_BACKEND: BACKEND_NETGATE},
    )
    netgate.add_to_hass(hass)
    result = await hass.config_entries.options.async_init(netgate.entry_id)
    keys = {str(k): k for k in result["data_schema"].schema}
    assert keys["firmware_install_unverified"].default() is False


@pytest.mark.asyncio
async def test_safe_upgrade_options(hass: HomeAssistant):
    """Safe upgrade needs a password; a blank password keeps the stored one."""
    netgate = MockConfigEntry(
        domain=DOMAIN,
        version=5,
        unique_id="safe",
        data={CONF_URL: "https://10.0.0.2:8443", CONF_BACKEND: BACKEND_NETGATE},
    )
    netgate.add_to_hass(hass)
    result = await hass.config_entries.options.async_init(netgate.entry_id)
    keys = {str(k): k for k in result["data_schema"].schema}
    assert keys["firmware_safe_upgrade"].default() is False
    assert keys["firmware_keep_packages"].default() == "Nexus, Netgate_Firmware_Upgrade"
    assert "firmware_backup_password" in keys

    result = await hass.config_entries.options.async_configure(
        result["flow_id"], user_input={"firmware_safe_upgrade": True}
    )
    assert result["errors"] == {"firmware_backup_password": "backup_password_required"}
    result = await hass.config_entries.options.async_configure(
        result["flow_id"],
        user_input={"firmware_safe_upgrade": True, "firmware_backup_password": "pw"},
    )
    assert result["type"] == FlowResultType.CREATE_ENTRY
    assert netgate.options["firmware_backup_password"] == "pw"

    result = await hass.config_entries.options.async_init(netgate.entry_id)
    result = await hass.config_entries.options.async_configure(
        result["flow_id"],
        user_input={"firmware_safe_upgrade": True, "firmware_backup_password": ""},
    )
    assert result["type"] == FlowResultType.CREATE_ENTRY
    assert netgate.options["firmware_backup_password"] == "pw"
