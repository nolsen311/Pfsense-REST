# pfSense-Pro — Netgate REST API v2 Migration

Working plan for migrating this Home Assistant integration off XML-RPC and onto the
pfSense REST API v2 (target: pfSense 26.07+).

Repo: https://github.com/nolsen311/Pfsense-pro (fork of DonTranQuiL/pfsense-pro)

## Status of this document

Rewritten after connecting to a **live pfSense 26.07-RELEASE box running REST API
package v2.10.2**. Every "VERIFY" item from the first draft has been resolved
against the live OpenAPI schema (`/api/v2/schema/openapi`) and real responses.
Sample responses for every endpoint the integration touches were captured and
should become test fixtures (redact hostnames / IPs / serial / `netgate_id` /
MACs before committing).

A few things the test box does **not** exercise are marked **LIVE-CHECK** — resolve
them on hardware that has the feature before shipping that piece:

- OpenVPN server status shape (`switch.py` / telemetry openvpn) — no servers configured.
- CARP `carp_status` value vocabulary — no CARP virtual IPs configured.
- `GET /api/v2/system/packages` shape — no add-on packages installed (it 500s in
  that state, see Firmware section).
- Whether `DELETE /api/v2/diagnostics/arp_table/entry` accepts an IP string for `id`.

Resolved on hardware since the first draft — see "Findings from live hardware" below:
`DELETE /api/v2/firewall/states` source/dest filtering; the `disabled` field on
GUI-authored rules; `PATCH /firewall/rule` and empty `statetype`.

The integration has since been rewritten and shipped (all seven phases below are
done; see repo history through `v0.10.1`). This document is now two things: the
reference for pfRest behaviour, and — in "Project state & conventions" — how the
repo is built, tested and released.

## Findings from live hardware

Discovered running the shipped integration against the live Netgate 6100
(26.07-RELEASE, pfRest v2.10.2). These are pfRest behaviours, not integration
bugs, and matter to anyone touching the same endpoints.

### `disabled` is wrong for rules disabled in the pfSense web UI

`GET /api/v2/firewall/rules` (and the NAT list endpoints) return
`"disabled": false` for **every rule that was disabled through the pfSense
webConfigurator**, even though the GUI shows them disabled and pf is not loading
them. Confirmed against a rule whose `config.xml` literally contains
`<disabled></disabled>`.

Cause: pfRest models `disabled` as a `BooleanField` with the default
`indicates_true: ''`, and `BooleanField::_from_internal()` does a **strict**
`$internal_value === $this->indicates_true` comparison. pfSense's own GUI writes
the content-less element `<disabled></disabled>`, which pfSense's XML parser
loads as an empty array (not `''`), so `[] === ''` is false and pfRest reports
`false`. Rules disabled **through the REST API** store pfRest's own `''` token
and round-trip correctly.

Consequence: `is_on = not rule.get("disabled")` is correct code fed bad data —
GUI-disabled rules show as ON in Home Assistant. There is no clean client-side
fix; the API genuinely does not expose the real state for these rules. Report
upstream (https://github.com/pfrest/pfSense-pkg-RESTAPI) and/or check for a newer
package. `git blame` the `disabled` handling before assuming the integration is
at fault.

### `PATCH /firewall/rule` rejects a blank `statetype`

`PATCH /api/v2/firewall/rule {"id": N, "disabled": <bool>}` returns
`400 FIELD_EMPTY_NOT_ALLOWED: Field 'statetype' cannot be empty` for any rule
whose `statetype` is `""` in the config — again, the GUI writes
`<statetype></statetype>` for some rules (mostly `block`/`reject`). pfRest
re-validates the **whole** object on a PATCH, so an unrelated toggle fails.

Same root cause family: `statetype` is a `StringField(default: 'keep state',
choices: [...])` with no `allow_empty`, and `''` is present-but-invalid so the
default never applies.

Workaround shipped in the client (`_set_rule_disabled` /
`_RULE_REQUIRED_DEFAULTS`): when the rule's `statetype` is falsy, include
`"statetype": "keep state"` (pfSense's own default, a behavioural no-op) in the
PATCH body. Extend the table if other empty-but-required fields surface.

### `DELETE /api/v2/firewall/states` — the filter works

The earlier LIVE-CHECK is resolved. The **prefix** filter is reliable:

- `DELETE /api/v2/firewall/states?source__startswith=<prefix>` and
  `?destination__startswith=<prefix>` both delete the matching states.
  State endpoints render as `ip:port` (IPv4), so a host is `"10.1.1.1:"` and an
  octet-aligned network is its leading octets plus a dot (`"10.0.10."`).
- `limit=0` means "no limit" for both GET and DELETE — a single call deletes
  **every** matching state, no per-call cap. (`limit=100000` behaves
  pathologically; use `0`.)
- The DELETE response `data` is the list of deleted state objects, so `len(data)`
  is the deleted count.
- Not usable for non-octet-aligned CIDRs (e.g. `/25`) or IPv6 via `startswith`;
  the shipped `kill_states_for_rule` skips those rather than shelling out.
- Exact-match query params (`source=<ip>`) did **not** work with a bare IP; only
  the `__startswith` / `__contains` operators matched.

### Aside: HACS "no update available"

If a release goes unnoticed by HACS, check for a **version regression** — HACS
compares versions semantically and treats a lower `manifest.json` / tag as a
downgrade. This fork's manifest was briefly at `3.0.0` before the first `0.9.x`
tags existed; anyone whose HACS recorded `2.x`/`3.x` must remove and re-add the
integration. Keep the tag, `manifest.json`, and shipped content in lockstep
(see `.github/workflows/release.yml`, which now *verifies* tag == manifest
rather than rewriting the manifest after the tag).

## Project state & conventions

Everything below the migration plan is done and released. This section is the
current state of the repo — read it before touching tooling, tests or a release.

### Identity

- Repo: `nolsen311/Pfsense-REST` (was `Pfsense-REST` created from, then
  **de-forked** from, `DonTranQuiL/Pfsense-pro` so PRs don't land upstream).
  HACS name is "Pfsense Pro"; integration `domain` is `pfsense`.
- The `pfsense` domain shares its brand icon with `travisghansen/hass-pfsense`
  via `home-assistant/brands` (`custom_integrations/pfsense/`, added upstream in
  2021). Nothing icon-related lives in this repo; a 0-byte `brand/icon.png` stub
  is dead weight. Changing the domain would forfeit the inherited icon.

### Lint / format

- `pyproject.toml` `[tool.ruff]` is the **Home Assistant core selection,
  verbatim** (kept in sync manually with `home-assistant/core`'s `pyproject.toml`).
  There is **no** project-specific ignore block — the whole codebase passes
  `ruff check .` and `ruff format --check .` against the full HA rule set.
  `required-version = ">=0.16.5"`.
- Two per-file-ignores beyond HA's: `tests/**` also ignores `SLF001` (tests poke
  internals) and relative imports are allowed under `custom_components/*/*`.
- A handful of `# noqa` with reasons remain in-tree (`C901` on the two
  entity-builder callbacks in `sensor.py`; `PLC0415` on the deferred
  `services.py` import that breaks a cycle; `BLE001` is not actually raised by
  modern ruff on the log-and-continue handlers).
- `.github/workflows/codechecker.yml` pins **`ruff==0.16.6`** and runs
  `ruff check --fix . && ruff format .`, then `git-auto-commit`s the result
  onto the branch (`ref: ${{ github.head_ref || github.ref_name }}` so it's not
  a detached checkout). Bump the pin and the `pyproject.toml` rules together.

### Tests

- `tests/` is a package (`tests/__init__.py`). Run:
  `pytest -v tests/ --cov=custom_components/pfsense/`.
- Uses `aioresponses` (not `respx`) for the client unit tests and
  `pytest-homeassistant-custom-component` for the entity/setup tests.
- HA-version gotchas that were hit and fixed — keep them in mind:
  - `DataUpdateCoordinator(...)` **must** be passed `config_entry=entry`, and
    `async_config_entry_first_refresh()` is only valid while the entry is in
    `SETUP_IN_PROGRESS`. Setup tests must go through
    `hass.config_entries.async_setup(entry.entry_id)`, not call
    `async_setup_entry(hass, entry)` directly.
- CI workflow is `.github/workflows/hass-ci.yml` (Python 3.13, `pull_request` +
  `push` to `main`, path-filtered to `custom_components/**` and `tests/**`).

### Release process

1. Bump `custom_components/pfsense/manifest.json` `version` in a normal commit
   on the feature branch. **Never let the tag out-run the manifest** — that was
   the 0.9.x tag/manifest-lag bug.
2. Merge to `main` (a merge commit or rebase, so per-commit history survives).
3. Create a GitHub Release: tag `v<version>` on `main`, publish (not draft, not
   pre-release). `.github/workflows/release.yml` (trigger: `release: published`)
   **verifies `v<version>` == `manifest.json` version** and fails loudly on a
   mismatch, then builds and attaches `pfsense.zip`. It no longer edits the
   manifest.
4. `.github/workflows/release-drafter.yml` drafts notes from PR labels
   (config: `.github/release-drafter.yml`); its suggested version is a plain
   patch bump off the last tag — override the tag when it's wrong.
- Version must only ever increase (HACS treats a lower manifest/tag as a
  downgrade and shows no update — see the HACS aside above).
- Released so far: `v0.9.0`, `v0.9.1`, `v0.9.3` (skipped `v0.9.2`), `v0.10.0`;
  `v0.10.1` in progress (docs/tooling + the CARP binary sensor now enabled by
  default).

## Target environment (confirmed)

| Fact | Value |
| --- | --- |
| pfSense | `26.07-RELEASE` (base `26.07`, patch `0`) |
| REST API package | community **pfSense-pkg-RESTAPI v2.10.2** (`pfrest`; Netgate ships it, it is not a separate fork) |
| API base path | `/api/v2/` |
| API port | **non-standard** on this box (`8444`); the GUI/HAProxy is on `443`, and `8443` is an unrelated API. The config flow must take a full base URL including port. |
| Auth header | `x-api-key: <key>` (schema also offers `BasicAuth` and `JWTAuth`; we use the key) |
| Schema URL | `https://<host>:<port>/api/v2/schema/openapi` (JSON; **not** `openapi.json`). Swagger UI at `/api/v2/documentation`. |
| Success envelope | `{"code":200,"status":"ok","response_id":"SUCCESS","message":"","data":{...},"_links":{}}` |
| Error envelope | same shape, non-2xx `code`, human `message`, machine `response_id` (e.g. `AUTH_AUTHENTICATION_FAILED`, `MODEL_REQUIRES_ID`, `MODELSET_FIRST_REQUESTED_WITH_NO_MODEL_OBJECTS`) |
| Bad/missing key | HTTP `401` + `response_id: AUTH_AUTHENTICATION_FAILED` |
| GraphQL | `POST /api/v2/graphql` present |
| Apply model | writes are staged; **`?apply=true` exists only on `DELETE`** for firewall/routing resources — `POST`/`PATCH` have no apply param and no `apply` body field, so a separate `POST /api/v2/{firewall,routing}/apply` call is required |

## Decisions already made (don't re-litigate)

1. **Full replacement, REST v2 only.** No XML-RPC fallback; installs without the
   REST API package (or below its minimum) are out of scope for this fork.
2. **Auth: API key via `x-api-key`.** The config flow's `password` field is
   replaced by `api_key`. `username` becomes informational or is dropped.
3. **Native async.** `aiohttp` via
   `homeassistant.helpers.aiohttp_client.async_get_clientsession(hass)`. Rationale:
   the repo already leans this way (`respx` is in `requirements*.txt`), it is the
   HA norm, it removes the `async_add_executor_job` indirection in `__init__.py` /
   `config_flow.py`, removes the `_apply_timeout` global-socket-timeout hack, and
   lets the poll fan out with `asyncio.gather`. `pypfsense` client methods become
   coroutines. Swap `respx` → `aioresponses` in the test requirements.
4. **Config-entry schema bumps to v3** with a reauth flow (an API key cannot be
   derived from a stored password).

## Connection / auth layer

- Base URL: user-entered, e.g. `https://pfsense.example:8444`. Keep scheme + netloc
  (+ port), append `/api/v2`.
- Send `x-api-key: <key>` on every request. Respect a `verify_ssl` option
  (`ClientSession` with an ssl context, or `ssl=False`).
- Parse the envelope; treat non-2xx `code` as an error carrying `response_id` +
  `message`.
- Config-flow error mapping:
  - `401` / `AUTH_AUTHENTICATION_FAILED` → `invalid_auth`
  - `403` → `privilege_missing`
  - DNS failure / connection refused → `cannot_connect`
  - TLS cert verification failure → `cannot_connect_ssl`
  - `404` on `GET /api/v2/system/version` → dedicated "REST API package not
    installed, or wrong port" error
- Validation probe for "add integration": `GET /api/v2/status/system` — returns the
  full device identity in one call.
- Use `aiohttp.ClientTimeout`; the reboot/halt calls will drop the connection —
  catch the timeout/`ClientError` and treat it as success, not failure.
- No XML-RPC mutex exists anymore. Reads may run concurrently; **write→apply pairs
  must be serialized behind an `asyncio.Lock`** (concurrent `/apply` calls race).

## Consumer contracts that must not break (or must be migrated)

The risky part of this rewrite is not the HTTP calls — it is four shapes that
other files are hard-coded to. Preserve them, or migrate deliberately.

1. **Poll-state dict** built by `PfSenseData.update()` in
   [custom_components/pfsense/__init__.py](custom_components/pfsense/__init__.py).
   Entities read `system_info`, `host_firmware_version`, `telemetry`, `config`,
   `services`, `carp_interfaces`, `carp_status`, `dhcp_leases`, `dhcp_stats`,
   `notices`, `arp_table`, `firmware_update_info`, `update_time`, `previous_state`
   directly. Keep the keys; change how they are filled. (`notices` is being
   removed — see below.)

2. **`state["config"]`** is read in only two places:
   [switch.py](custom_components/pfsense/switch.py) (`config.filter.rule`,
   `config.nat.rule`, `config.nat.outbound.rule` — used to *construct* the rule
   switch entities and read `tracker` / `created.time` / `descr` /
   `associated-rule-id` / `disabled`) and
   [sensor.py:398](custom_components/pfsense/sensor.py#L398)
   (`config.system.dnsserver`). There is no raw-config endpoint by design.
   Replace with discrete fetches; `switch.py` entity construction is a rewrite,
   not a re-plumb.

3. **`state["telemetry"]` nested shape.** `sensor.py` and the rate math in
   `__init__.py` (lines ~326–433) are keyed to
   `telemetry.interfaces.{name}.{counter}`,
   `telemetry.gateways.{name}.{prop}`,
   `telemetry.openvpn.servers.{vpnid}.{prop}`, `telemetry.cpu.*`,
   `telemetry.memory.*`, `telemetry.system.*`, `telemetry.filesystems[]`,
   `telemetry.wan_ip`, `telemetry.pfblockerng.*`. The new client should rebuild
   this exact dict from the decomposed REST calls in an internal
   `_build_telemetry()` adapter, so `sensor.py` / `const.py` do not all churn at
   once. Prune the `SENSOR_TYPES` entries whose source no longer exists (list
   under "Confirmed breaking changes").

4. **Entity `unique_id` roots.** `slugify(system_info["netgate_device_id"])` feeds
   every entity's `unique_id` and the device-registry identifier
   ([__init__.py:510](custom_components/pfsense/__init__.py#L510),
   [device_tracker.py:44](custom_components/pfsense/device_tracker.py#L44)); rule
   switches key off `tracker`, NAT switches off `created.time`, CARP sensors off
   `uniqid`. **All four values are still exposed by REST** (`netgate_id`,
   `tracker`, `created_time`, `uniqid`), so no entity-registry migration is
   needed — only the config-entry password→api_key migration.

## Actually-consumed client surface

Roughly half of the old client is dead code — not referenced anywhere outside
`custom_components/pfsense/pypfsense/`. **Do not port** `get_gateways`,
`get_gateway`, `get_gateway_status`, `get_gateways_status`, `get_virtual_ips`,
`get_carp_interface_status`, `get_interface`, `get_interface_by_description`,
`get_configured_interface_descriptions`, `get_interfaces`, `arp_get_mac_by_ip`,
`get_system_serial`, `get_netgate_device_id`, `get_firmware_update_info` (as its
own call). Interface/gateway/VIP data all arrives through `get_telemetry()` today.

The methods the integration actually calls, and their REST replacements:

### System identity & version

- `get_system_info()` → `GET /api/v2/status/system`
  → `{platform, serial, netgate_id, uptime, bios_*, kernel_pti, mds_mitigation,
  temp_c, temp_f, cpu_model, cpu_load_avg[3], cpu_count, cpu_usage, mbuf_usage,
  mem_usage, swap_usage, disk_usage}` — plus `GET /api/v2/system/hostname`
  → `{hostname, domain}`. Build
  `system_info = {hostname, domain, serial, netgate_device_id: <netgate_id>, platform}`.
- `get_host_firmware_version()` → `GET /api/v2/system/version`
  → `{version:"26.07-RELEASE", base:"26.07", patch:"0", buildtime:"20260807-1926"}`.
  `PfSenseEntity.device_info` currently reads
  `host_firmware_version["platform"]` and `["firmware"]["version"]` — remap:
  `platform` from `/status/system`, version string from here.

### Telemetry — `get_telemetry()` decomposes into

- `GET /api/v2/status/system` — CPU / mem / temp / load / uptime / mbuf / swap /
  disk. **All usage figures are pre-computed floats (percent).** `cpu_usage`
  replaces the two-snapshot tick-delta computation in `__init__.py` (delete lines
  ~326–354 that maintain `telemetry.cpu.used_percent` from `ticks.total/idle`).
  `cpu_load_avg` is `[one_minute, five_minute, fifteen_minute]`. `uptime` is a
  **human string** ("10 Days 08 Hours 14 Minutes 51 Seconds") — no epoch
  `boottime`. `mbuf_usage` / `swap_usage` were `null` on the Netgate 6100 test box.
- `GET /api/v2/status/interfaces` →
  `[{id, name, descr, hwif, macaddr, mtu, enable, status, ipaddr, subnet,
  linklocal, ipaddrv6, subnetv6, inerrs, outerrs, collisions, inbytes,
  inbytespass, outbytes, outbytespass, inpkts, inpktspass, outpkts, outpktspass,
  dhcplink, media, gateway, gatewayv6}]`. Key the telemetry dict by `name`
  (= old `ifname`). **No `*block` counters** (`inbytesblock` etc.) → drop the
  interface block-traffic sensors. `if` is `hwif` now.
- `GET /api/v2/status/gateways` →
  `[{id, name, srcip, monitorip, delay, stddev, loss, status, substatus}]`. Key by
  `name`. The old `gateways_detail` extras (`weight`, `interface`, `isdefaultgw`,
  `gateway`) come from `GET /api/v2/routing/gateways` +
  `GET /api/v2/routing/gateway/default` (`{defaultgw4, defaultgw6}` — compute
  `isdefaultgw` by comparing names).
- `GET /api/v2/status/openvpn/servers` → **LIVE-CHECK**. Schema:
  `[{name, mode, port, vpnid, mgmt, conns:[{common_name, bytes_recv, bytes_sent,
  connect_time, ...}], routes:[...]}]`. Build
  `{name, vpnid, connected_client_count: len(conns),
  total_bytes_recv: sum(bytes_recv), total_bytes_sent: sum(bytes_sent)}` keyed by
  `vpnid`, matching the old shape.
- `wan_ip` → from `/api/v2/status/interfaces` where `name == "wan"`, field
  `ipaddr` (fallback string "Disconnected" as today).
- `pfblockerng` dnsbl / ip block counts → **no endpoint**. Either
  `POST /api/v2/diagnostics/command_prompt {"command":"wc -l < /var/log/pfblockerng/dnsbl.log"}`
  (output is capped at 1024 chars — fine for an integer) or drop the two sensors.
- No REST source for: mbuf used/total counts, memory byte breakdown
  (`physmem`/`usermem`/`realmem`/`swap_total`/`swap_reserved`), CPU frequency,
  per-filesystem disk usage, epoch `boottime`. Drop those `SENSOR_TYPES`.
- Consider `POST /api/v2/graphql` to pull `status/system` + `status/interfaces` +
  `status/gateways` in a single request and cut the poll round-trip count.

### Services

- `get_services()` → `GET /api/v2/status/services` →
  `[{id, name, description, enabled, status}]` (`status` is a bool). Note: the
  DHCP service is `kea-dhcp4` (Kea), not `dhcpd`. **LIVE-CHECK** how OpenVPN
  instances appear — `switch.py` keys OpenVPN service switches off
  `service["vpnid"]` + `service["description"]`; if the list has no `vpnid` the
  special-casing in `switch.py` / `sensor.py` must change.
- `start_service` / `stop_service` / `restart_service` →
  `POST /api/v2/status/service {"id": <int>, "action": "start"|"stop"|"restart"}`.
  `restart_service_if_running` = read `status`, then restart if true. Drop the
  `vpnid` / `vpnmode` / `mode` munging unless LIVE-CHECK shows OpenVPN still needs it.

### DHCP leases

- `get_dhcp_leases()` → `GET /api/v2/status/dhcp_server/leases` →
  `[{id, ip, mac, hostname, if, starts, ends, active_status, online_status, descr}]`.
- `__init__.py` lease-stats loop: `lease["act"]` → `active_status` (skip
  `"expired"`; other values seen: `static`, `active`), `lease["online"]` →
  `online_status` (values seen: `active/online`, `idle/offline` — the existing
  match lists already cover them).
- `config_flow.py` device picker and `device_tracker.py` read `mac-address` /
  `ip-address` — but they read those from the **ARP table**, not leases (see next).

### ARP table / device tracker

- `get_arp_table()` → `GET /api/v2/diagnostics/arp_table` →
  `[{id, hostname, ip_address, mac_address, interface, type, permanent,
  dnsresolve, expires}]`. Renames in `config_flow.py` + `device_tracker.py`:
  `ip-address` → `ip_address`, `mac-address` → `mac_address`. `hostname` is still
  `"?"` when unknown (keep the `.strip("?")`). `interface` is the description
  ("LAN") now. `expires` is a string ("Expires in 411 seconds").
- `delete_arp_entry(ip)` → `DELETE /api/v2/diagnostics/arp_table/entry?id=<id>`.
  **LIVE-CHECK** whether `id` accepts an IP string; if not, GET the table, find
  the row by `ip_address`, DELETE by numeric `id` (extra round-trip). This is
  called per connected tracked device per poll in
  [device_tracker.py:315](custom_components/pfsense/device_tracker.py#L315) —
  reconsider (only on transition to disconnected, or drop the behaviour).

### Gateways

- `set_default_gateway(gw, ip_version)` →
  `PATCH /api/v2/routing/gateway/default {"defaultgw4"|"defaultgw6": "<name>"}`
  then `POST /api/v2/routing/apply`. Replaces the old raw-PHP
  `write_config` + `system_routing_configure()` + … block.

### Firewall / NAT rule switches

- Lists: `GET /api/v2/firewall/rules`, `GET /api/v2/firewall/nat/port_forwards`,
  `GET /api/v2/firewall/nat/outbound/mappings` (note "mappings", not "rule").
  Each item has `id` (array index), `disabled` (real **bool** now, was `""`
  presence), `descr`, `associated_rule_id`, `created_time` (int), and — rules
  only — `tracker` (int).
- `switch.py` construction: firewall rules keep matching on `tracker`; NAT keeps
  matching on `created.time` → `created_time` (same unix value). Slugified
  `unique_id` keys are unchanged. `is_on` = `not disabled`.
- enable/disable → `PATCH /api/v2/firewall/rule {"id": <int>, "disabled": <bool>}`
  then `POST /api/v2/firewall/apply`. Same pattern for `nat/port_forward` and
  `nat/outbound/mapping`. **`PATCH` takes no `?apply=` param — the separate apply
  call is mandatory.** Server-side `query[...]` filtering was unreliable in
  testing (returned unfiltered results); keep finding rules client-side.
- **`disabled` is unreliable on read** — pfRest reports `false` for rules
  disabled via the pfSense GUI (see "Findings from live hardware"). `is_on`
  looks backwards for those rules and there is no client-side fix.
- **`statetype` gotcha on write** — a bare `{"id", "disabled"}` PATCH 400s with
  `FIELD_EMPTY_NOT_ALLOWED` on rules whose `statetype` is blank; the client
  backfills `"statetype": "keep state"`. Same section.

### Aliases

- `update_alias_address(name, address, action)` → `GET /api/v2/firewall/aliases`,
  find by `name`, then
  `PATCH /api/v2/firewall/alias {"id": <int>, "address": [...], "detail": [...]}`
  (`address` and `detail` are **real JSON arrays** now — no more space / `||`
  joins), then `POST /api/v2/firewall/apply`, then kill states for the address
  (see State table).

### CARP / virtual IPs

- `get_carp_status()` → `GET /api/v2/status/carp` →
  `{enable: <bool>, maintenance_mode: <bool>}`.
  `PfSenseCarpStatusBinarySensor` uses this as a bool → use `enable`
  (or `enable and not maintenance_mode`).
- `get_carp_interfaces()` → `GET /api/v2/firewall/virtual_ips`, filter
  `mode == "carp"` →
  `[{uniqid, mode, interface, type, subnet, subnet_bits, descr, vhid, advbase,
  advskew, carp_status, carp_mode, carp_peer}]`. `carp_status` is inline, so the
  old per-VIP status call collapses away. **LIVE-CHECK** the `carp_status` value
  vocabulary (MASTER / BACKUP / INIT?) — no VIPs on the test box. `sensor.py`
  keys off `uniqid` (preserved) and reads `vhid` / `advskew` / `advbase` /
  `subnet` / `subnet_bits` (all present); `type` is present too.

### State table

- `reset_state_table()` → `DELETE /api/v2/firewall/states` — pass **`limit=0`**
  ("no limit"; a single call clears everything). The default page is 100.
- `kill_states(source, destination)` — still uses `pfctl -k` via
  `command_prompt` (the client keeps this for the service). For the
  rule-switch state reset, `kill_states_for_rule` instead uses
  `DELETE /api/v2/firewall/states?{source,destination}__startswith=<prefix>`
  with `limit=0` — the prefix filter is confirmed working on hardware (see
  "Findings from live hardware"). `startswith` can't express `/25`-style
  networks or IPv6, which that path deliberately skips.

### System control

- `system_reboot()` → `POST /api/v2/diagnostics/reboot` (empty body). The old
  `fsck` / `reroot` modes are not supported — drop them or shell out via
  `command_prompt`. Expect the connection to drop mid-request.
- `system_halt()` → `POST /api/v2/diagnostics/halt_system` (empty body).

### Wake-on-LAN

- `send_wol(interface, mac)` →
  `POST /api/v2/services/wake_on_lan/send {"interface": ..., "mac_addr": ...}`.
  The endpoint handles the subnet-broadcast detail server-side.

### DNS servers (wan_ip sensor attributes)

- `config.system.dnsserver` → `GET /api/v2/system/dns` →
  `{dnsallowoverride, dnslocalhost, dnsserver: [...]}`.

### exec services

- `exec_command(command, background)` →
  `POST /api/v2/diagnostics/command_prompt {"command": ...}` →
  `{output, result_code}` (output truncated at 1024 chars). No `background`
  equivalent — append `&` to the command string, or drop the flag.
- `exec_php(script)` → **no equivalent. Remove the service.** Breaking change.

### Notices — removed

There is no endpoint for `are_notices_pending` / `get_notices` / `file_notice` /
`close_notice`. **Remove** `PfSensePendingNoticesPresentBinarySensor`, the
`close_notice` and `file_notice` services, and the `notices` key in the poll
state. (Weak optional substitute: `GET /api/v2/status/logs/system`.)

### Firmware update entity — degraded

- No base-system "update available" flag anywhere.
  `GET /api/v2/system/packages` is add-on packages only
  (`{name, installed_version, latest_version, update_available}`) and **returns
  HTTP 500 (`MODELSET_FIRST_REQUESTED_WITH_NO_MODEL_OBJECTS`) when no packages are
  installed** — must be caught. `GET /api/v2/system/package/available` lists the
  catalogue.
- `upgrade_firmware()` + `pid_is_running()` → `POST /api/v2/system/update`
  triggers an upgrade with no PID / progress reporting.
- Options: **(a)** make `update.py` read-only (drop `UpdateEntityFeature.INSTALL`;
  show installed vs latest where available); **(b)** drive `pfSense-upgrade -c` /
  `-d` through `command_prompt` and parse; **(c)** drop the platform. Recommend
  (a) for the first release.

## Confirmed breaking changes (changelog / README)

1. Authentication is now an **API key**, not username/password. Existing config
   entries require re-auth (a key cannot be derived from a stored password).
2. The API may be on a **non-standard port** — it must be included in the URL.
3. `pfsense.exec_php` service removed.
4. Notices removed: `binary_sensor.<device>_pending_notices_present`,
   `pfsense.close_notice`, `pfsense.file_notice`.
5. Sensors removed (no REST data source): Memory Buffers used/total/percent,
   Memory Physmem/Usermem/Realmem/Swap Total/Swap Reserved, CPU Frequency
   Current/Max, per-filesystem "Filesystem Used Percentage", System Boottime,
   interface `*block` traffic counters (in/out bytes & packets blocked).
6. `update` entity loses one-click install (becomes read-only) unless implemented
   via `command_prompt`.
7. `pfsense.system_reboot` loses the `fsck` / `reroot` modes.
8. pfBlockerNG block-count sensors depend on a `command_prompt` log grep; they are
   dropped if that privilege is not granted to the API key's user.

## Config entry & migration

- `const.py`: add `CONF_API_KEY`. Keep `CONF_USERNAME` optional/informational or
  remove it. Remove password constants from the flow.
- `config_flow.py` `VERSION` 2 → 3. `async_migrate_entry`: for v2 entries, drop
  `CONF_PASSWORD` and trigger reauth (`ConfigEntryAuthFailed` / a `reauth` step)
  so the user pastes an API key. The unique id stays `slugify(<netgate_id>)`,
  which equals the old `slugify(netgate_device_id)` value, so entities re-attach
  cleanly.
- Add a `reauth` step to the config flow.

## Async client shape

- `pypfsense.Client` methods become `async def`, using a shared
  `aiohttp.ClientSession` from `async_get_clientsession(hass)`.
- `PfSenseData.update()` becomes async; fan out the independent reads
  (`status/system`, `status/interfaces`, `status/services`, `status/gateways`,
  `status/openvpn/servers`, `status/dhcp_server/leases`, `status/carp`,
  `firewall/virtual_ips`, `firewall/rules`, `nat/*`, `system/dns`) with
  `asyncio.gather`. Device-tracker scope fetches only `diagnostics/arp_table`.
- Remove `hass.async_add_executor_job` wrappers in `__init__.py` and
  `config_flow.py`. Remove `_apply_timeout` (use `aiohttp.ClientTimeout`).
- One `asyncio.Lock` around every write→`/apply` sequence.
- `manifest.json` needs no new `requirements` entry (`aiohttp` is in HA core).
  **Keep `mac-vendor-lookup`** — it is OUI lookup for the device tracker and is
  unrelated to the transport.

## Manifest / housekeeping

All done — recorded here for history:

- `manifest.json` `documentation` / `issue_tracker` now point at
  `nolsen311/Pfsense-REST`; `codeowners` is `@nolsen311`.
- `respx` → `aioresponses` in the test requirements.
- The `ai_engineer/` directory and its GitHub Actions were removed.
- `README.md` was rewritten for REST v2 and carries the fork-origin / de-fork
  note; the badges point at `nolsen311/Pfsense-REST` and the real workflows.

## Phased order (all shipped in `v0.10.0`)

All seven phases are complete; kept for the record.

1. **Auth / connection layer + async `pypfsense` skeleton + config flow.** API-key
   entry, non-standard port, reauth step, error mapping, v3 migration. Get "add
   integration" working end-to-end against the live box.
2. **Core status.** `status/system` (identity + telemetry base), `status/interfaces`,
   `status/services`, `status/gateways`. Build the `_build_telemetry()` adapter
   here. Integration boots; core sensors / service switches populate.
3. **`config` blob removal.** `firewall/rules` + `nat/*` list fetches + `switch.py`
   entity-construction rewrite; `system/dns` for the wan_ip attributes.
4. **DHCP leases + ARP** (device-tracker coordinator; field renames).
5. **Remaining telemetry.** OpenVPN status, load average, temperature, optional
   pfBlockerNG grep; prune dead `SENSOR_TYPES` and their entities.
6. **Actions.** gateway default + `routing/apply`, WOL, reboot/halt, state table,
   alias update + `firewall/apply`, `exec_command`. Drop `exec_php` and notices.
7. **`update.py` read-only. README + manifest + changelog.**

## Testing

See "Project state & conventions → Tests" above for how the suite is wired
today. Original intent, still valid:

- `aioresponses` for request-construction, envelope-parsing, and error-handling
  unit tests — all coverable without hardware.
- Not unit-testable: that a `PATCH` + `/apply` actually commits on-box; the
  OpenVPN / CARP / package response shapes (absent on the test box). Smoke-test
  those on real hardware. The state-table `__startswith` delete and the
  `disabled` / `statetype` behaviours *were* verified on hardware — see
  "Findings from live hardware".

## Reference

- Live box: `https://pfsense.sneakyblueshoes.int:8444/api/v2` — schema at
  `/api/v2/schema/openapi`, Swagger UI at `/api/v2/documentation`.
- Package: https://github.com/pfrest/pfSense-pkg-RESTAPI (v2.10.2) —
  docs https://pfrest.org
- GraphQL: `POST /api/v2/graphql`
- Ansible collection with request/response examples:
  https://github.com/pfrest/ansible-collection-pfsense
