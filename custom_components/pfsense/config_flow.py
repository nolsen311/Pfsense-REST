"""Config flow for the pfSense integration (REST API v2)."""

from __future__ import annotations

import logging
from urllib.parse import urlparse

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import (
    CONF_NAME,
    CONF_PASSWORD,
    CONF_SCAN_INTERVAL,
    CONF_URL,
    CONF_USERNAME,
    CONF_VERIFY_SSL,
)
from homeassistant.core import callback
from homeassistant.data_entry_flow import AbortFlow
from homeassistant.helpers.aiohttp_client import async_get_clientsession
import homeassistant.helpers.config_validation as cv
from homeassistant.helpers.selector import (
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)
from homeassistant.util import slugify

from .const import (
    AUTH_METHOD_API_KEY,
    AUTH_METHOD_BASIC,
    AUTH_METHOD_JWT,
    AUTH_METHOD_NETGATE,
    CONF_API_KEY,
    CONF_AUTH_METHOD,
    CONF_DEVICE_TRACKER_CONSIDER_HOME,
    CONF_DEVICE_TRACKER_ENABLED,
    CONF_DEVICE_TRACKER_SCAN_INTERVAL,
    CONF_DEVICES,
    CONF_FIRMWARE_BACKUP_PASSWORD,
    CONF_FIRMWARE_INSTALL_UNVERIFIED,
    CONF_FIRMWARE_KEEP_PACKAGES,
    CONF_FIRMWARE_SAFE_UPGRADE,
    CONF_RULE_SWITCH_KILL_STATES,
    DEFAULT_DEVICE_TRACKER_CONSIDER_HOME,
    DEFAULT_DEVICE_TRACKER_ENABLED,
    DEFAULT_DEVICE_TRACKER_SCAN_INTERVAL,
    DEFAULT_FIRMWARE_INSTALL_UNVERIFIED,
    DEFAULT_FIRMWARE_KEEP_PACKAGES,
    DEFAULT_FIRMWARE_SAFE_UPGRADE,
    DEFAULT_RULE_SWITCH_KILL_STATES,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_VERIFY_SSL,
    DOMAIN,
)
from .pypfsense import (
    BACKEND_NETGATE,
    BACKEND_PFREST,
    CONF_BACKEND,
    PfSenseAuthError,
    PfSenseConnectionError,
    PfSenseNotFoundError,
    PfSensePrivilegeError,
    client_from_config,
)

_LOGGER = logging.getLogger(__name__)

_EXAMPLE_URL = "https://pfsense.local:8444"
_EXAMPLE_URLS = {AUTH_METHOD_NETGATE: "https://pfsense.local:8443"}

# Credential fields shown per auth method (besides URL / verify_ssl / name).
_CRED_FIELDS: dict[str, tuple[str, ...]] = {
    AUTH_METHOD_API_KEY: (CONF_API_KEY,),
    AUTH_METHOD_BASIC: (CONF_USERNAME, CONF_PASSWORD),
    AUTH_METHOD_JWT: (CONF_USERNAME, CONF_PASSWORD),
    AUTH_METHOD_NETGATE: (CONF_USERNAME, CONF_PASSWORD),
}


_AUTH_METHODS = (
    AUTH_METHOD_NETGATE,
    AUTH_METHOD_API_KEY,
    AUTH_METHOD_BASIC,
    AUTH_METHOD_JWT,
)
_NETGATE_PORT = 8443


def _reconfigure_defaults(entry: config_entries.ConfigEntry, method: str) -> dict:
    """Pre-fill the reconfigure form from the entry (never the secrets).

    Keeps the URL when the backend stays the same. When switching to the
    Netgate API, the host is kept and the port becomes 8443; when switching
    back to the REST API package, the port is left for the user to enter.
    """
    data = entry.data
    url = str(data.get(CONF_URL) or "")
    if _backend_for(method) != data.get(CONF_BACKEND, BACKEND_PFREST) and url:
        parts = urlparse(url)
        host = parts.hostname or ""
        if ":" in host:  # IPv6 literal
            host = f"[{host}]"
        port = f":{_NETGATE_PORT}" if method == AUTH_METHOD_NETGATE else ""
        url = f"{parts.scheme or 'https'}://{host}{port}"
    defaults = {
        CONF_URL: url,
        CONF_VERIFY_SSL: data.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL),
    }
    if CONF_USERNAME in _CRED_FIELDS[method] and data.get(CONF_USERNAME):
        defaults[CONF_USERNAME] = data[CONF_USERNAME]
    return defaults


def _backend_for(method: str) -> str:
    return BACKEND_NETGATE if method == AUTH_METHOD_NETGATE else BACKEND_PFREST


def _creds(method: str, user_input: dict) -> dict:
    """The entry data that selects the backend and holds its credentials."""
    return {
        CONF_BACKEND: _backend_for(method),
        CONF_AUTH_METHOD: method,
        **{f: str(user_input[f]).strip() for f in _CRED_FIELDS[method]},
    }


class InvalidURL(Exception):
    """The URL is missing a scheme or host."""


def _normalize_url(raw: str) -> str:
    parts = urlparse(raw.strip())
    if not parts.scheme or not parts.netloc:
        raise InvalidURL
    return f"{parts.scheme}://{parts.netloc}"


def _cred_schema(method: str, defaults: dict) -> dict:
    """Return a voluptuous schema fragment for one method's credential fields."""
    return {
        vol.Required(field, default=defaults.get(field, "")): str
        for field in _CRED_FIELDS[method]
    }


async def _get_system_info(hass, url: str, verify_ssl: bool, creds: dict) -> dict:
    """Build the right client and return its system_info, or raise a typed error."""
    session = async_get_clientsession(hass, verify_ssl)
    client = client_from_config(url, session, creds, verify_ssl)
    return await client.get_system_info()


class ConfigFlowHandler(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for pfSense."""

    # v3 == XML-RPC -> REST API v2 (api key only).
    # v4 == multi-method auth; entries carry ``auth_method``.
    # v5 == entries carry ``backend`` (pfrest or the Netgate official API).
    VERSION = 5

    def __init__(self) -> None:
        """Initialize the flow state."""
        self._reauth_entry: config_entries.ConfigEntry | None = None

    async def async_step_user(self, user_input=None):
        """Let the user pick an authentication method."""
        return self.async_show_menu(
            step_id="user",
            menu_options=list(_AUTH_METHODS),
        )

    async def async_step_netgate(self, user_input=None):
        """Configure Netgate's official API (Nexus, username + password)."""
        return await self._auth_step(AUTH_METHOD_NETGATE, user_input)

    async def async_step_api_key(self, user_input=None):
        """Configure API-key auth."""
        return await self._auth_step(AUTH_METHOD_API_KEY, user_input)

    async def async_step_basic(self, user_input=None):
        """Configure username + password (HTTP Basic) auth."""
        return await self._auth_step(AUTH_METHOD_BASIC, user_input)

    async def async_step_jwt(self, user_input=None):
        """Configure JWT auth (token minted from username + password)."""
        return await self._auth_step(AUTH_METHOD_JWT, user_input)

    async def _auth_step(self, method: str, user_input, reconfigure: bool = False):
        """Show the per-method form and validate the connection on submit.

        With ``reconfigure`` the existing entry is updated in place (any
        backend or auth method, same firewall) instead of creating one.
        """
        errors: dict[str, str] = {}
        submitted = user_input is not None
        user_input = user_input or {}
        defaults = (
            _reconfigure_defaults(self._get_reconfigure_entry(), method)
            if reconfigure and not submitted
            else user_input
        )

        if submitted:
            creds = _creds(method, user_input)
            verify_ssl = user_input.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL)
            name = user_input.get(CONF_NAME) or None
            try:
                url = _normalize_url(user_input[CONF_URL])
                system_info = await _get_system_info(self.hass, url, verify_ssl, creds)

                await self.async_set_unique_id(
                    slugify(system_info["netgate_device_id"])
                )
                data = {CONF_URL: url, CONF_VERIFY_SSL: verify_ssl, **creds}
                if reconfigure:
                    # Same firewall only: entity unique ids hang off its id.
                    self._abort_if_unique_id_mismatch(reason="wrong_device")
                    return self.async_update_reload_and_abort(
                        self._get_reconfigure_entry(), data=data
                    )
                self._abort_if_unique_id_configured()

                if name is None:
                    name = "{}.{}".format(
                        system_info.get("hostname"), system_info.get("domain")
                    )

                return self.async_create_entry(title=name, data=data)
            except InvalidURL:
                errors["base"] = "invalid_url_format"
            except PfSenseAuthError:
                errors["base"] = "invalid_auth"
            except PfSensePrivilegeError:
                errors["base"] = "privilege_missing"
            except PfSenseNotFoundError:
                errors["base"] = "api_not_found"
            except PfSenseConnectionError as err:
                text = str(err).lower()
                if "certificate" in text or "ssl" in text:
                    errors["base"] = "cannot_connect_ssl"
                else:
                    errors["base"] = "cannot_connect"
            except AbortFlow:
                raise  # already_configured / wrong_device, not an error
            except Exception:
                _LOGGER.exception("Unexpected error validating pfSense connection")
                errors["base"] = "unknown"

        schema = {
            vol.Required(CONF_URL, default=defaults.get(CONF_URL, "")): str,
            **_cred_schema(method, defaults),
            vol.Optional(
                CONF_VERIFY_SSL,
                default=defaults.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL),
            ): bool,
        }
        if not reconfigure:
            schema[vol.Optional(CONF_NAME, default=defaults.get(CONF_NAME, ""))] = str
        return self.async_show_form(
            step_id=f"reconfigure_{method}" if reconfigure else method,
            data_schema=vol.Schema(schema),
            errors=errors,
            description_placeholders={
                "example_url": _EXAMPLE_URLS.get(method, _EXAMPLE_URL)
            },
        )

    async def async_step_reconfigure(self, user_input=None):
        """Change how an entry connects: switch backend/auth, URL or credentials."""
        return self.async_show_menu(
            step_id="reconfigure",
            menu_options=[f"reconfigure_{m}" for m in _AUTH_METHODS],
        )

    async def async_step_reconfigure_netgate(self, user_input=None):
        """Reconfigure onto Netgate's official API."""
        return await self._auth_step(AUTH_METHOD_NETGATE, user_input, reconfigure=True)

    async def async_step_reconfigure_api_key(self, user_input=None):
        """Reconfigure onto the REST API package with an API key."""
        return await self._auth_step(AUTH_METHOD_API_KEY, user_input, reconfigure=True)

    async def async_step_reconfigure_basic(self, user_input=None):
        """Reconfigure onto the REST API package with username + password."""
        return await self._auth_step(AUTH_METHOD_BASIC, user_input, reconfigure=True)

    async def async_step_reconfigure_jwt(self, user_input=None):
        """Reconfigure onto the REST API package with JWT."""
        return await self._auth_step(AUTH_METHOD_JWT, user_input, reconfigure=True)

    async def async_step_import(self, user_input):
        """Handle YAML import (legacy entries carried an API key)."""
        return await self.async_step_api_key(user_input)

    async def async_step_reauth(self, entry_data):
        """Triggered when auth fails, or by an older-version migration."""
        self._reauth_entry = self.hass.config_entries.async_get_entry(
            self.context["entry_id"]
        )
        return await self.async_step_reauth_confirm()

    async def async_step_reauth_confirm(self, user_input=None):
        """Re-prompt for whichever credentials the entry's auth method needs."""
        errors: dict[str, str] = {}
        entry = self._reauth_entry
        assert entry is not None
        method = entry.data.get(CONF_AUTH_METHOD, AUTH_METHOD_API_KEY)

        if user_input is not None:
            url = entry.data[CONF_URL]
            verify_ssl = entry.data.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL)
            creds = _creds(method, user_input)
            try:
                system_info = await _get_system_info(self.hass, url, verify_ssl, creds)
            except PfSenseAuthError:
                errors["base"] = "invalid_auth"
            except PfSensePrivilegeError:
                errors["base"] = "privilege_missing"
            except (PfSenseConnectionError, PfSenseNotFoundError):
                errors["base"] = "cannot_connect"
            except Exception:
                _LOGGER.exception("Unexpected error during pfSense reauth")
                errors["base"] = "unknown"
            else:
                new_unique_id = slugify(system_info["netgate_device_id"])
                if entry.unique_id and entry.unique_id != new_unique_id:
                    return self.async_abort(reason="wrong_device")
                self.hass.config_entries.async_update_entry(
                    entry,
                    data={CONF_URL: url, CONF_VERIFY_SSL: verify_ssl, **creds},
                )
                await self.hass.config_entries.async_reload(entry.entry_id)
                return self.async_abort(reason="reauth_successful")

        return self.async_show_form(
            step_id="reauth_confirm",
            data_schema=vol.Schema(_cred_schema(method, {})),
            errors=errors,
            description_placeholders={"name": entry.title},
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry):
        """Return the options flow handler."""
        return OptionsFlowHandler()


class OptionsFlowHandler(config_entries.OptionsFlow):
    """Handle the pfSense options flow."""

    def __init__(self) -> None:
        """Initialize the flow state."""
        self.new_options: dict | None = None

    async def async_step_init(self, user_input=None):
        """Handle the options form."""
        errors: dict[str, str] = {}
        if user_input is not None:
            user_input = dict(user_input)
            # The password field is never pre-filled: blank keeps the stored one.
            if not user_input.get(CONF_FIRMWARE_BACKUP_PASSWORD):
                user_input.pop(CONF_FIRMWARE_BACKUP_PASSWORD, None)
                if old := self.config_entry.options.get(CONF_FIRMWARE_BACKUP_PASSWORD):
                    user_input[CONF_FIRMWARE_BACKUP_PASSWORD] = old
            if user_input.get(CONF_FIRMWARE_SAFE_UPGRADE) and not user_input.get(
                CONF_FIRMWARE_BACKUP_PASSWORD
            ):
                errors[CONF_FIRMWARE_BACKUP_PASSWORD] = "backup_password_required"
            elif user_input.get(CONF_DEVICE_TRACKER_ENABLED):
                self.new_options = user_input
                return await self.async_step_device_tracker()
            else:
                return self.async_create_entry(title="", data=user_input)

        opts = self.config_entry.options
        base_schema = {
            vol.Optional(
                CONF_SCAN_INTERVAL,
                default=opts.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL),
            ): vol.All(vol.Coerce(int), vol.Clamp(min=10, max=300)),
            vol.Optional(
                CONF_DEVICE_TRACKER_ENABLED,
                default=opts.get(
                    CONF_DEVICE_TRACKER_ENABLED, DEFAULT_DEVICE_TRACKER_ENABLED
                ),
            ): bool,
            vol.Optional(
                CONF_DEVICE_TRACKER_SCAN_INTERVAL,
                default=opts.get(
                    CONF_DEVICE_TRACKER_SCAN_INTERVAL,
                    DEFAULT_DEVICE_TRACKER_SCAN_INTERVAL,
                ),
            ): vol.All(vol.Coerce(int), vol.Clamp(min=30, max=300)),
            vol.Optional(
                CONF_DEVICE_TRACKER_CONSIDER_HOME,
                default=opts.get(
                    CONF_DEVICE_TRACKER_CONSIDER_HOME,
                    DEFAULT_DEVICE_TRACKER_CONSIDER_HOME,
                ),
            ): vol.All(vol.Coerce(int), vol.Clamp(min=0, max=600)),
            vol.Optional(
                CONF_RULE_SWITCH_KILL_STATES,
                default=opts.get(
                    CONF_RULE_SWITCH_KILL_STATES,
                    DEFAULT_RULE_SWITCH_KILL_STATES,
                ),
            ): bool,
        }
        if self.config_entry.data.get(CONF_BACKEND) == BACKEND_NETGATE:
            base_schema[
                vol.Optional(
                    CONF_FIRMWARE_INSTALL_UNVERIFIED,
                    default=opts.get(
                        CONF_FIRMWARE_INSTALL_UNVERIFIED,
                        DEFAULT_FIRMWARE_INSTALL_UNVERIFIED,
                    ),
                )
            ] = bool
            base_schema[
                vol.Optional(
                    CONF_FIRMWARE_SAFE_UPGRADE,
                    default=opts.get(
                        CONF_FIRMWARE_SAFE_UPGRADE, DEFAULT_FIRMWARE_SAFE_UPGRADE
                    ),
                )
            ] = bool
            base_schema[vol.Optional(CONF_FIRMWARE_BACKUP_PASSWORD)] = TextSelector(
                TextSelectorConfig(type=TextSelectorType.PASSWORD)
            )
            base_schema[
                vol.Optional(
                    CONF_FIRMWARE_KEEP_PACKAGES,
                    default=opts.get(
                        CONF_FIRMWARE_KEEP_PACKAGES, DEFAULT_FIRMWARE_KEEP_PACKAGES
                    ),
                )
            ] = str
        return self.async_show_form(
            step_id="init", data_schema=vol.Schema(base_schema), errors=errors
        )

    async def async_step_device_tracker(self, user_input=None):
        """Let the user pick which MACs to track from the live ARP table."""
        entry = self.config_entry
        url = entry.data[CONF_URL]
        verify_ssl = entry.data.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL)
        session = async_get_clientsession(self.hass, verify_ssl)
        client = client_from_config(url, session, entry.data, verify_ssl)

        if user_input is None and (arp_table := await client.get_arp_table(True)):
            selected_devices = entry.options.get(CONF_DEVICES, [])
            entries = {device: device for device in selected_devices}
            for row in arp_table:
                mac = (row.get("mac_address") or "").lower()
                if not mac:
                    continue
                hostname = (row.get("hostname") or "").strip("?").strip()
                ip = (row.get("ip_address") or "").strip()
                entries[mac] = f"{mac} - {hostname} ({ip})"

            return self.async_show_form(
                step_id="device_tracker",
                data_schema=vol.Schema(
                    {
                        vol.Optional(
                            CONF_DEVICES, default=selected_devices
                        ): cv.multi_select(entries),
                    }
                ),
            )

        if user_input:
            self.new_options[CONF_DEVICES] = user_input[CONF_DEVICES]
        return self.async_create_entry(title="", data=self.new_options)
