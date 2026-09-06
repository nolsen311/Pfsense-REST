"""Service switch tests."""

from unittest.mock import AsyncMock, MagicMock, PropertyMock, patch

import pytest
from homeassistant.components.switch import SwitchEntityDescription
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.pfsense.switch import PfSenseServiceSwitch


@pytest.fixture
def mock_coordinator():
    coord = MagicMock()
    coord.data = {
        "services": [
            {"id": 6, "name": "unbound", "status": True, "description": "DNS Resolver"}
        ]
    }
    coord.async_refresh = AsyncMock()
    return coord


@pytest.mark.asyncio
@patch(
    "custom_components.pfsense.PfSenseEntity.pfsense_device_unique_id",
    new_callable=PropertyMock,
    return_value="test",
)
@patch(
    "custom_components.pfsense.PfSenseEntity.pfsense_device_name",
    new_callable=PropertyMock,
    return_value="pfSense",
)
async def test_service_switch_turn_off(mock_name, mock_uid, mock_coordinator):
    desc = SwitchEntityDescription(key="service.unbound.status", name="unbound")
    switch = PfSenseServiceSwitch(MockConfigEntry(), mock_coordinator, desc)

    client = AsyncMock()
    switch._get_pfsense_client = MagicMock(return_value=client)

    assert switch.is_on is True

    await switch.async_turn_off()
    client.stop_service.assert_awaited_once_with(
        "unbound",
        {"id": 6, "name": "unbound", "status": True, "description": "DNS Resolver"},
    )
    mock_coordinator.async_refresh.assert_awaited_once()
