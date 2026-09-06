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
from homeassistant.helpers.aiohttp_client import async_get_clientsession
import homeassistant.helpers.config_validation as cv
from homeassistant.util import slugify

from .const import (
    AUTH_METHOD_API_KEY,
    AUTH_METHOD_BASIC,
    AUTH_METHOD_JWT,
    CONF_API_KEY,
    CONF_AUTH_METHOD,
    CONF_DEVICE_TRACKER_CONSIDER_HOME,
    CONF_DEVICE_TRACKER_ENABLED,
    CONF_DEVICE_TRACKER_SCAN_INTERVAL,
    CONF_DEVICES,
    CONF_RULE_SWITCH_KILL_STATES,
    DEFAULT_DEVICE_TRACKER_CONSIDER_HOME,
    DEFAULT_DEVICE_TRACKER_ENABLED,
    DEFAULT_DEVICE_TRACKER_SCAN_INTERVAL,
    DEFAULT_RULE_SWITCH_KILL_STATES,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_VERIFY_SSL,
    DOMAIN,
)
from .pypfsense import (
    PfSenseAuthError,
    PfSenseConnectionError,
    PfSenseNotFoundError,
    PfSensePrivilegeError,
    client_from_config,
)

_LOGGER = logging.getLogger(__name__)

_EXAMPLE_URL = "https://pfsense.local:8444"

# Credential fields shown per auth method (besides URL / verify_ssl / name).
_CRED_FIELDS: dict[str, tuple[str, ...]] = {
    AUTH_METHOD_API_KEY: (CONF_API_KEY,),
    AUTH_METHOD_BASIC: (CONF_USERNAME, CONF_PASSWORD),
    AUTH_METHOD_JWT: (CONF_USERNAME, CONF_PASSWORD),
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
    VERSION = 4

    def __init__(self) -> None:
        """Initialize the flow state."""
        self._reauth_entry: config_entries.ConfigEntry | None = None

    async def async_step_user(self, user_input=None):
        """Let the user pick an authentication method."""
        return self.async_show_menu(
            step_id="user",
            menu_options=[
                AUTH_METHOD_API_KEY,
                AUTH_METHOD_BASIC,
                AUTH_METHOD_JWT,
            ],
        )

    async def async_step_api_key(self, user_input=None):
        """Configure API-key auth."""
        return await self._auth_step(AUTH_METHOD_API_KEY, user_input)

    async def async_step_basic(self, user_input=None):
        """Configure username + password (HTTP Basic) auth."""
        return await self._auth_step(AUTH_METHOD_BASIC, user_input)

    async def async_step_jwt(self, user_input=None):
        """Configure JWT auth (token minted from username + password)."""
        return await self._auth_step(AUTH_METHOD_JWT, user_input)

    async def _auth_step(self, method: str, user_input):
        """Show the per-method form and validate the connection on submit."""
        errors: dict[str, str] = {}
        user_input = user_input or {}

        if user_input:
            creds = {
                CONF_AUTH_METHOD: method,
                **{f: str(user_input[f]).strip() for f in _CRED_FIELDS[method]},
            }
            verify_ssl = user_input.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL)
            name = user_input.get(CONF_NAME) or None
            try:
                url = _normalize_url(user_input[CONF_URL])
                system_info = await _get_system_info(self.hass, url, verify_ssl, creds)

                await self.async_set_unique_id(
                    slugify(system_info["netgate_device_id"])
                )
                self._abort_if_unique_id_configured()

                if name is None:
                    name = "{}.{}".format(
                        system_info.get("hostname"), system_info.get("domain")
                    )

                return self.async_create_entry(
                    title=name,
                    data={CONF_URL: url, CONF_VERIFY_SSL: verify_ssl, **creds},
                )
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
            except Exception:
                _LOGGER.exception("Unexpected error validating pfSense connection")
                errors["base"] = "unknown"

        schema = {
            vol.Required(CONF_URL, default=user_input.get(CONF_URL, "")): str,
            **_cred_schema(method, user_input),
            vol.Optional(
                CONF_VERIFY_SSL,
                default=user_input.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL),
            ): bool,
            vol.Optional(CONF_NAME, default=user_input.get(CONF_NAME, "")): str,
        }
        return self.async_show_form(
            step_id=method,
            data_schema=vol.Schema(schema),
            errors=errors,
            description_placeholders={"example_url": _EXAMPLE_URL},
        )

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
            creds = {
                CONF_AUTH_METHOD: method,
                **{f: str(user_input[f]).strip() for f in _CRED_FIELDS[method]},
            }
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
        if user_input is not None:
            if user_input.get(CONF_DEVICE_TRACKER_ENABLED):
                self.new_options = user_input
                return await self.async_step_device_tracker()
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
        return self.async_show_form(step_id="init", data_schema=vol.Schema(base_schema))

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
