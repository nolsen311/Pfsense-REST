"""Config flow tests for the REST API v2 auth model."""

from unittest.mock import AsyncMock, patch

import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.pfsense.const import (
    CONF_API_KEY,
    CONF_DEVICE_TRACKER_ENABLED,
    CONF_DEVICES,
    DOMAIN,
)
from custom_components.pfsense.pypfsense import PfSenseAuthError
from homeassistant.const import CONF_URL, CONF_VERIFY_SSL
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


@pytest.mark.asyncio
async def test_form_user_success(hass: HomeAssistant):
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": "user"}
    )
    with (
        patch(
            "custom_components.pfsense.config_flow.Client",
            return_value=_client_mock(),
        ),
        patch("custom_components.pfsense.async_setup_entry", return_value=True),
    ):
        result2 = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {
                CONF_URL: "https://192.168.1.1:8444",
                CONF_API_KEY: "abc123",
                CONF_VERIFY_SSL: False,
            },
        )
    assert result2["type"] == FlowResultType.CREATE_ENTRY
    assert result2["title"] == "router.local"
    assert result2["data"] == {
        CONF_URL: "https://192.168.1.1:8444",
        CONF_API_KEY: "abc123",
        CONF_VERIFY_SSL: False,
    }


@pytest.mark.asyncio
async def test_form_user_invalid_auth(hass: HomeAssistant):
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": "user"}
    )
    client = AsyncMock()
    client.get_system_info.side_effect = PfSenseAuthError("bad key")
    with patch("custom_components.pfsense.config_flow.Client", return_value=client):
        result2 = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {CONF_URL: "https://192.168.1.1:8444", CONF_API_KEY: "nope"},
        )
    assert result2["type"] == FlowResultType.FORM
    assert result2["errors"]["base"] == "invalid_auth"


@pytest.mark.asyncio
async def test_reauth_flow_updates_key(hass: HomeAssistant):
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=3,
        unique_id="mock_id_12345",
        data={CONF_URL: "https://192.168.1.1:8444", CONF_VERIFY_SSL: False},
    )
    entry.add_to_hass(hass)

    result = await entry.start_reauth_flow(hass)
    assert result["step_id"] == "reauth_confirm"

    with (
        patch(
            "custom_components.pfsense.config_flow.Client",
            return_value=_client_mock(),
        ),
        patch("custom_components.pfsense.async_setup_entry", return_value=True),
    ):
        result2 = await hass.config_entries.flow.async_configure(
            result["flow_id"], {CONF_API_KEY: "freshkey"}
        )
    assert result2["type"] == FlowResultType.ABORT
    assert result2["reason"] == "reauth_successful"
    assert entry.data[CONF_API_KEY] == "freshkey"


@pytest.mark.asyncio
async def test_options_flow(hass: HomeAssistant):
    entry = MockConfigEntry(
        domain=DOMAIN,
        version=3,
        data={
            CONF_URL: "https://192.168.1.1:8444",
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
    with patch("custom_components.pfsense.config_flow.Client", return_value=client):
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
