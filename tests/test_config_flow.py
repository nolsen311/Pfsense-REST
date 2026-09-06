"""Config flow tests for the REST API v2 multi-method auth model."""

from unittest.mock import AsyncMock, patch

import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.pfsense.const import (
    AUTH_METHOD_API_KEY,
    AUTH_METHOD_BASIC,
    AUTH_METHOD_JWT,
    CONF_API_KEY,
    CONF_AUTH_METHOD,
    CONF_DEVICE_TRACKER_ENABLED,
    CONF_DEVICES,
    DOMAIN,
)
from custom_components.pfsense.pypfsense import PfSenseAuthError
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
