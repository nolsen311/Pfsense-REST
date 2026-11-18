"""Safe firmware upgrade: Netgate's recommended steps around a pfSense upgrade.

Netgate's upgrade guide: "The safest practice is to remove all packages
before upgrading ... note the installed packages, remove them, perform the
upgrade, and then reinstall when the upgrade is complete", after taking a
config backup. This runs that sequence on the Netgate API:

1. ``snapshot``: a boot environment, to roll back to.
2. ``backup``: the whole config, encrypted by pfSense, saved under
   ``<config>/pfsense_backups/``.
3. ``removing``: uninstall every add-on package except the keep list (Nexus
   always stays: it is the API this integration talks to).
4. ``upgrading``: start the firmware upgrade; the firewall reboots.
5. ``reinstalling``: once the installed version changes, reinstall the
   removed packages (their settings stay in config.xml).

The plan is saved after every step, so it survives the firewall's reboot
and a Home Assistant restart. A failure before the upgrade starts reinstalls
whatever was removed and leaves the firmware alone. A failed or timed-out
upgrade leaves the packages removed and raises a repair listing them; it
clears itself once they are installed again.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import datetime
import logging
import os
import time
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.storage import Store
from homeassistant.util import dt as dt_util, slugify

from .const import (
    ALWAYS_KEEP_PACKAGES,
    CONF_FIRMWARE_BACKUP_PASSWORD,
    CONF_FIRMWARE_KEEP_PACKAGES,
    DEFAULT_FIRMWARE_KEEP_PACKAGES,
    DOMAIN,
)
from .pypfsense import PfSenseError

_LOGGER = logging.getLogger(__name__)

STORAGE_VERSION = 1
BACKUP_DIR = "pfsense_backups"
ISSUE_SAFE_UPGRADE = "safe_upgrade_incomplete"

UPGRADE_TIMEOUT = 2 * 60 * 60  # no new version after this: give up
PACKAGE_WAIT = 5 * 60  # per package removal
REINSTALL_WAIT = 30 * 60
POLL_EVERY = 10.0

# Stages while the sequence is running (the entity shows "installing").
ACTIVE_STAGES = ("snapshot", "backup", "removing", "upgrading", "reinstalling")
FAILED = "failed"


def keep_list(value: str | None) -> set[str]:
    """Package names to keep, from the comma-separated option, plus Nexus."""
    names = {
        part.strip().removeprefix("pfSense-pkg-")
        for part in (
            value if value is not None else DEFAULT_FIRMWARE_KEEP_PACKAGES
        ).split(",")
    }
    return {n for n in names if n} | ALWAYS_KEEP_PACKAGES


class SafeUpgrade:
    """Runs and tracks one entry's safe upgrade."""

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        get_client: Callable[[], Any],
    ) -> None:
        """Set up storage for ``entry``; call :meth:`async_load` before use."""
        self.hass = hass
        self.entry = entry
        self._get_client = get_client
        self._store: Store[dict] = Store(
            hass, STORAGE_VERSION, f"{DOMAIN}.safe_upgrade.{entry.entry_id}"
        )
        self.plan: dict | None = None
        self._task: asyncio.Task | None = None
        self._listeners: list[Callable[[], None]] = []

    # ------------------------------------------------------------- state

    @property
    def stage(self) -> str | None:
        """Current stage, or ``None`` when nothing is running or pending."""
        return (self.plan or {}).get("stage")

    @property
    def in_progress(self) -> bool:
        """True from the snapshot until the packages are back."""
        return self.stage in ACTIVE_STAGES

    def attributes(self) -> dict:
        """What the firmware entity shows while (or after) running."""
        plan = self.plan or {}
        return {
            "safe_upgrade_stage": plan.get("stage"),
            "safe_upgrade_from": plan.get("from_version"),
            "safe_upgrade_boot_environment": plan.get("boot_environment"),
            "safe_upgrade_backup": plan.get("backup_file"),
            "safe_upgrade_removed_packages": plan.get("removed", []),
            "safe_upgrade_error": plan.get("error"),
        }

    @callback
    def async_add_listener(self, listener: Callable[[], None]) -> Callable[[], None]:
        """Call ``listener`` whenever the plan changes."""
        self._listeners.append(listener)
        return lambda: self._listeners.remove(listener)

    async def _save(self, **changes) -> None:
        if changes:
            self.plan = {**(self.plan or {}), **changes}
        if self.plan is None:
            await self._store.async_remove()
        else:
            await self._store.async_save(self.plan)
        for listener in list(self._listeners):
            listener()

    # ------------------------------------------------------------- start

    async def async_load(self) -> None:
        """Restore a plan saved before a restart."""
        self.plan = await self._store.async_load()
        stage = self.stage
        if stage in ("snapshot", "backup", "removing"):
            # The run was cut off before the upgrade started.
            await self._fail("Home Assistant restarted before the upgrade started")
        elif stage == "reinstalling":
            self._start(self._reinstall())
        elif stage == FAILED:
            self._raise_issue()

    async def async_start(self, from_version: str | None) -> None:
        """Begin the sequence; returns once it is running in the background."""
        if self.in_progress:
            raise HomeAssistantError("A safe upgrade is already running")
        if self.stage == FAILED and not self.plan.get("packages_back"):
            raise HomeAssistantError(
                "The last safe upgrade did not finish; reinstall its removed "
                "packages (see Repairs) before starting another"
            )
        ir.async_delete_issue(self.hass, DOMAIN, self._issue_id)
        password = self.entry.options.get(CONF_FIRMWARE_BACKUP_PASSWORD)
        if not password:
            raise HomeAssistantError("Set a config backup password under Configure")
        self.plan = {
            "stage": "snapshot",
            "from_version": from_version,
            "started": time.time(),
            "removed": [],
        }
        await self._save()
        self._start(self._prepare(password))

    def _start(self, coro) -> None:
        self._task = self.entry.async_create_background_task(
            self.hass, coro, f"{DOMAIN} safe upgrade {self.entry.title}"
        )

    # ------------------------------------------------------- the sequence

    async def _prepare(self, password: str) -> None:
        """Steps 1-4. Any failure here reinstalls what was removed."""
        client = self._get_client()
        try:
            name = await client.create_boot_environment()
            await self._save(stage="backup", boot_environment=name)

            data = await client.download_config_backup(password)
            path = await self.hass.async_add_executor_job(self._write_backup, data)
            await self._save(stage="removing", backup_file=path)

            keep = keep_list(self.entry.options.get(CONF_FIRMWARE_KEEP_PACKAGES))
            packages = await client.get_installed_packages(refresh=True)
            for pkg in packages:
                if pkg["name"] in keep:
                    continue
                await client.remove_package(pkg["package"])
                await self._wait_for(
                    lambda names, n=pkg["name"]: n not in names, PACKAGE_WAIT
                )
                await self._save(removed=[*self.plan["removed"], pkg["package"]])

            await client.start_firmware_update()
            await self._save(stage="upgrading", upgrade_started=time.time())
            _LOGGER.warning(
                "Safe upgrade of %s started from %s (boot environment %s, "
                "backup %s, removed %s)",
                self.entry.title,
                self.plan.get("from_version"),
                self.plan.get("boot_environment"),
                self.plan.get("backup_file"),
                ", ".join(self.plan["removed"]) or "no packages",
            )
        except (PfSenseError, OSError, TimeoutError) as err:
            _LOGGER.error(
                "Safe upgrade of %s stopped before upgrading: %s", self.entry.title, err
            )
            await self._save(error=f"{self.stage}: {err}")
            if self.plan["removed"]:
                await self._save(stage="reinstalling", aborted=True)
                await self._reinstall()
            else:
                await self._fail(f"{self.stage}: {err}")

    async def _reinstall(self) -> None:
        """Step 5: put the removed packages back."""
        removed = list((self.plan or {}).get("removed") or [])
        client = self._get_client()
        try:
            if removed:
                await client.install_packages(removed)
                wanted = {p.removeprefix("pfSense-pkg-") for p in removed}
                await self._wait_for(lambda names: wanted <= names, REINSTALL_WAIT)
        except (PfSenseError, TimeoutError) as err:
            await self._fail(f"reinstalling packages: {err}")
            return
        if (self.plan or {}).get("aborted"):
            # Nothing was upgraded; the error is still worth surfacing.
            await self._fail(
                f"{self.plan.get('error')}; the removed packages were reinstalled "
                "and the firmware was not upgraded",
                packages_back=True,
            )
            return
        _LOGGER.info("Safe upgrade of %s finished", self.entry.title)
        self.plan = None
        await self._save()
        ir.async_delete_issue(self.hass, DOMAIN, self._issue_id)

    async def _wait_for(self, done: Callable[[set[str]], bool], limit: float) -> None:
        client = self._get_client()
        deadline = time.monotonic() + limit
        while True:
            names = {
                p["name"] for p in await client.get_installed_packages(refresh=True)
            }
            if done(names):
                return
            if time.monotonic() > deadline:
                raise TimeoutError("timed out waiting for the package change")
            await asyncio.sleep(POLL_EVERY)

    def _write_backup(self, data: bytes) -> str:
        folder = self.hass.config.path(BACKUP_DIR)
        os.makedirs(folder, mode=0o700, exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        version = slugify(str((self.plan or {}).get("from_version") or "unknown"))
        base = os.path.join(folder, f"{slugify(self.entry.title)}-{version}-{stamp}")
        for n in range(100):
            path = f"{base}.xml" if n == 0 else f"{base}-{n}.xml"
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                continue
            with os.fdopen(fd, "wb") as fh:
                fh.write(data)
            return path
        raise OSError(f"could not pick a backup file name under {folder}")

    # ------------------------------------------------------------ polling

    @callback
    def async_on_poll(self, state: dict | None) -> None:
        """Advance on each coordinator update (new version seen, timeout)."""
        stage = self.stage
        if stage == "upgrading":
            base = ((state or {}).get("firmware_update_info") or {}).get("base") or {}
            installed = base.get("installed_version")
            if installed and installed != self.plan.get("from_version"):
                _LOGGER.info("pfSense is now %s; reinstalling packages", installed)
                self.plan["to_version"] = installed
                self.plan["stage"] = "reinstalling"
                self.hass.async_create_task(self._save())
                self._start(self._reinstall())
            elif time.time() - self.plan.get("upgrade_started", 0) > UPGRADE_TIMEOUT:
                self.hass.async_create_task(
                    self._fail(
                        "no new pfSense version two hours after starting the upgrade"
                    )
                )
        elif stage == FAILED and not self.plan.get("packages_back"):
            # Self-clearing once the removed packages are installed again.
            names = {p.get("name") for p in (state or {}).get("packages") or []}
            wanted = {
                p.removeprefix("pfSense-pkg-") for p in self.plan.get("removed") or []
            }
            if wanted <= names:
                self.hass.async_create_task(self.async_dismiss())

    async def async_dismiss(self) -> None:
        """Forget a finished or failed plan and its repair."""
        self.plan = None
        await self._save()
        ir.async_delete_issue(self.hass, DOMAIN, self._issue_id)

    # ------------------------------------------------------------- failure

    @property
    def _issue_id(self) -> str:
        return f"{ISSUE_SAFE_UPGRADE}_{self.entry.entry_id}"

    async def _fail(self, error: str, packages_back: bool = False) -> None:
        await self._save(
            stage=FAILED, error=error, packages_back=packages_back, failed=time.time()
        )
        self._raise_issue()

    def _raise_issue(self) -> None:
        plan = self.plan or {}
        removed = plan.get("removed") or []
        ir.async_create_issue(
            self.hass,
            DOMAIN,
            self._issue_id,
            is_fixable=False,
            severity=ir.IssueSeverity.ERROR,
            translation_key=ISSUE_SAFE_UPGRADE,
            translation_placeholders={
                "name": self.entry.title,
                "error": str(plan.get("error") or "unknown"),
                "packages": ", ".join(removed)
                if removed and not plan.get("packages_back")
                else "none",
                "boot_environment": str(plan.get("boot_environment") or "none"),
                "backup": str(plan.get("backup_file") or "none"),
                "when": dt_util.utc_from_timestamp(
                    plan.get("failed") or time.time()
                ).isoformat(),
            },
        )
