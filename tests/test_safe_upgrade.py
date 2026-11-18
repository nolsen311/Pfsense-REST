"""Tests for the safe firmware upgrade sequence."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.pfsense import safe_upgrade as su
from custom_components.pfsense.const import (
    CONF_FIRMWARE_BACKUP_PASSWORD,
    CONF_FIRMWARE_KEEP_PACKAGES,
    DOMAIN,
)
from custom_components.pfsense.pypfsense import PfSenseAPIError
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import issue_registry as ir

BACKUP = b"---- BEGIN config.xml ----\nENCRYPTED\n---- END config.xml ----\n"


class FakeFirewall:
    """A Netgate client whose package list follows removals and installs."""

    def __init__(self, names):
        """Start with packages ``names`` installed."""
        self.names = set(names)
        self.calls: list = []
        self.create_boot_environment = AsyncMock(side_effect=self._snapshot)
        self.download_config_backup = AsyncMock(return_value=BACKUP)
        self.start_firmware_update = AsyncMock(side_effect=self._upgrade)
        self.fail_remove: str | None = None

    async def _snapshot(self):
        self.calls.append("snapshot")
        return "quick-20261117165509"

    async def _upgrade(self):
        self.calls.append("upgrade")

    async def get_installed_packages(self, refresh=False):
        """List the installed packages."""
        return [
            {"name": n, "package": f"pfSense-pkg-{n}", "installed_version": "1"}
            for n in sorted(self.names)
        ]

    async def remove_package(self, package):
        """Remove one package (or fail on ``fail_remove``)."""
        name = package.removeprefix("pfSense-pkg-")
        if name == self.fail_remove:
            raise PfSenseAPIError(500, "", "removal failed")
        self.calls.append(f"remove {name}")
        self.names.discard(name)

    async def install_packages(self, packages):
        """Install packages."""
        self.calls.append(f"install {','.join(sorted(packages))}")
        self.names |= {p.removeprefix("pfSense-pkg-") for p in packages}


def _entry(tmp_options=None):
    return MockConfigEntry(
        domain=DOMAIN,
        title="router.local",
        entry_id="safe",
        data={},
        options={
            CONF_FIRMWARE_BACKUP_PASSWORD: "pw",
            CONF_FIRMWARE_KEEP_PACKAGES: "Netgate_Firmware_Upgrade",
            **(tmp_options or {}),
        },
    )


def _state(version, names=()):
    return {
        "firmware_update_info": {"base": {"installed_version": version}},
        "packages": [{"name": n} for n in names],
    }


@pytest.fixture(autouse=True)
def _fast():
    with patch.object(su, "POLL_EVERY", 0):
        yield


async def _run(hass, manager):
    if manager._task is not None:
        await manager._task
    await hass.async_block_till_done()


def test_keep_list():
    """Nexus is always kept; the prefix and blanks are tolerated."""
    assert su.keep_list("pfSense-pkg-acme, , haproxy") == {"acme", "haproxy", "Nexus"}
    assert su.keep_list(None) == {"Nexus", "Netgate_Firmware_Upgrade"}
    assert su.keep_list("") == {"Nexus"}


async def test_full_sequence(hass: HomeAssistant, tmp_path):
    """Snapshot, backup, remove (not the keep list), upgrade, then reinstall."""
    hass.config.config_dir = str(tmp_path)
    entry = _entry()
    entry.add_to_hass(hass)
    fw = FakeFirewall({"Nexus", "Netgate_Firmware_Upgrade", "acme", "softflowd"})
    manager = su.SafeUpgrade(hass, entry, lambda: fw)
    await manager.async_load()

    await manager.async_start("26.07")
    assert manager.in_progress
    await _run(hass, manager)
    assert fw.calls == ["snapshot", "remove acme", "remove softflowd", "upgrade"]
    assert manager.stage == "upgrading"
    assert manager.plan["boot_environment"] == "quick-20261117165509"
    path = manager.plan["backup_file"]
    assert path.startswith(str(tmp_path / "pfsense_backups"))
    backup = Path(path)
    assert await hass.async_add_executor_job(backup.read_bytes) == BACKUP
    mode = await hass.async_add_executor_job(lambda: backup.stat().st_mode & 0o777)
    assert mode == 0o600
    fw.download_config_backup.assert_awaited_once_with("pw")

    # Still the old version (or unreachable while it reboots): keep waiting.
    manager.async_on_poll(_state("26.07"))
    manager.async_on_poll(None)
    assert manager.stage == "upgrading"

    # The new version is up: reinstall what was removed, then finish.
    manager.async_on_poll(_state("26.10"))
    await _run(hass, manager)
    assert fw.calls[-1] == "install pfSense-pkg-acme,pfSense-pkg-softflowd"
    assert {"acme", "softflowd"} <= fw.names
    assert manager.plan is None and not manager.in_progress
    assert (
        ir.async_get(hass).async_get_issue(DOMAIN, "safe_upgrade_incomplete_safe")
        is None
    )


async def test_prepare_failure_reinstalls_and_skips_upgrade(
    hass: HomeAssistant, tmp_path
):
    """A removal failure puts back what was removed and never upgrades."""
    hass.config.config_dir = str(tmp_path)
    entry = _entry({CONF_FIRMWARE_KEEP_PACKAGES: ""})
    entry.add_to_hass(hass)
    fw = FakeFirewall({"Nexus", "acme", "softflowd"})
    fw.fail_remove = "softflowd"
    manager = su.SafeUpgrade(hass, entry, lambda: fw)
    await manager.async_load()

    await manager.async_start("26.07")
    await _run(hass, manager)
    assert "upgrade" not in fw.calls
    assert fw.calls == ["snapshot", "remove acme", "install pfSense-pkg-acme"]
    assert fw.names == {"Nexus", "acme", "softflowd"}
    assert manager.stage == su.FAILED
    issue = ir.async_get(hass).async_get_issue(DOMAIN, "safe_upgrade_incomplete_safe")
    assert issue.translation_placeholders["packages"] == "none"
    assert "removal failed" in issue.translation_placeholders["error"]
    # Packages are back, so a retry is allowed and clears the old repair.
    fw.fail_remove = None
    await manager.async_start("26.07")
    await _run(hass, manager)
    assert manager.stage == "upgrading"
    assert (
        ir.async_get(hass).async_get_issue(DOMAIN, "safe_upgrade_incomplete_safe")
        is None
    )


async def test_backup_failure_stops_before_removing(hass: HomeAssistant, tmp_path):
    """No backup, no removals, no upgrade."""
    hass.config.config_dir = str(tmp_path)
    entry = _entry()
    entry.add_to_hass(hass)
    fw = FakeFirewall({"Nexus", "acme"})
    fw.download_config_backup.side_effect = PfSenseAPIError(0, "", "not encrypted")
    manager = su.SafeUpgrade(hass, entry, lambda: fw)
    await manager.async_load()
    await manager.async_start("26.07")
    await _run(hass, manager)
    assert fw.calls == ["snapshot"]
    assert manager.stage == su.FAILED
    assert "backup" in manager.plan["error"]


async def test_upgrade_timeout_leaves_packages_and_raises_repair(
    hass: HomeAssistant, tmp_path
):
    """No new version in time: packages stay removed, repair lists them."""
    hass.config.config_dir = str(tmp_path)
    entry = _entry()
    entry.add_to_hass(hass)
    fw = FakeFirewall({"Nexus", "acme"})
    manager = su.SafeUpgrade(hass, entry, lambda: fw)
    await manager.async_load()
    await manager.async_start("26.07")
    await _run(hass, manager)
    manager.plan["upgrade_started"] -= su.UPGRADE_TIMEOUT + 1
    manager.async_on_poll(_state("26.07", {"Nexus"}))
    await hass.async_block_till_done()
    assert manager.stage == su.FAILED
    assert "acme" not in fw.names  # left removed, as chosen
    issue = ir.async_get(hass).async_get_issue(DOMAIN, "safe_upgrade_incomplete_safe")
    assert issue.translation_placeholders["packages"] == "pfSense-pkg-acme"
    assert issue.translation_placeholders["boot_environment"] == "quick-20261117165509"
    with pytest.raises(HomeAssistantError, match="did not finish"):
        await manager.async_start("26.07")

    # Reinstalled by hand: the repair and plan clear themselves.
    manager.async_on_poll(_state("26.07", {"Nexus", "acme"}))
    await hass.async_block_till_done()
    assert manager.plan is None
    assert (
        ir.async_get(hass).async_get_issue(DOMAIN, "safe_upgrade_incomplete_safe")
        is None
    )


async def test_plan_survives_restart(hass: HomeAssistant, tmp_path):
    """A plan saved mid-upgrade is picked up by a new manager."""
    hass.config.config_dir = str(tmp_path)
    entry = _entry()
    entry.add_to_hass(hass)
    fw = FakeFirewall({"Nexus", "acme"})
    first = su.SafeUpgrade(hass, entry, lambda: fw)
    await first.async_load()
    await first.async_start("26.07")
    await _run(hass, first)
    assert first.stage == "upgrading"

    second = su.SafeUpgrade(hass, entry, lambda: fw)
    await second.async_load()
    assert second.stage == "upgrading"
    assert second.plan["removed"] == ["pfSense-pkg-acme"]
    second.async_on_poll(_state("26.10"))
    await _run(hass, second)
    assert second.plan is None and "acme" in fw.names


async def test_restart_mid_prepare_is_a_failure(hass: HomeAssistant, tmp_path):
    """Cut off before the upgrade started: reported, packages listed."""
    hass.config.config_dir = str(tmp_path)
    entry = _entry()
    entry.add_to_hass(hass)
    store = su.Store(hass, su.STORAGE_VERSION, f"{DOMAIN}.safe_upgrade.safe")
    await store.async_save({"stage": "removing", "removed": ["pfSense-pkg-acme"]})
    manager = su.SafeUpgrade(hass, entry, lambda: FakeFirewall(set()))
    await manager.async_load()
    assert manager.stage == su.FAILED
    issue = ir.async_get(hass).async_get_issue(DOMAIN, "safe_upgrade_incomplete_safe")
    assert issue.translation_placeholders["packages"] == "pfSense-pkg-acme"


async def test_start_needs_a_password(hass: HomeAssistant):
    """No password: refuse before touching the firewall."""
    entry = _entry({CONF_FIRMWARE_BACKUP_PASSWORD: ""})
    entry.add_to_hass(hass)
    fw = FakeFirewall({"Nexus"})
    manager = su.SafeUpgrade(hass, entry, lambda: fw)
    await manager.async_load()
    with pytest.raises(HomeAssistantError, match="password"):
        await manager.async_start("26.07")
    assert fw.calls == []
