# pfSense-REST

A Home Assistant integration for pfSense® firewalls, built on the **pfSense REST
API v2** (`pfSense-pkg-RESTAPI`). It surfaces live system, interface, gateway,
DHCP and VPN telemetry as entities, and lets you drive firewall rules, NAT
rules, services, aliases and routing from Home Assistant.

[![Latest Release](https://img.shields.io/github/v/release/nolsen311/Pfsense-pro?style=for-the-badge&color=007ec6)](https://github.com/nolsen311/Pfsense-pro/releases)
[![License](https://img.shields.io/github/license/nolsen311/Pfsense-pro?style=for-the-badge&color=007ec6)](https://github.com/nolsen311/Pfsense-pro/blob/main/LICENSE)
[![Tests](https://img.shields.io/github/actions/workflow/status/nolsen311/Pfsense-pro/pytest.yml?style=for-the-badge&label=TESTS&color=5dbb0f)](https://github.com/nolsen311/Pfsense-pro/actions/workflows/pytest.yml)
[![HACS Validation](https://img.shields.io/github/actions/workflow/status/nolsen311/Pfsense-pro/hacs.yaml?style=for-the-badge&label=HACS&color=5dbb0f)](https://github.com/nolsen311/Pfsense-pro/actions/workflows/hacs.yaml)
[![HACS Custom](https://img.shields.io/badge/HACS-Custom-ff6e27?style=for-the-badge)](https://hacs.xyz/)

---

## Requirements

- **pfSense 26.07 or newer** with the **REST API v2 package** installed and enabled
  (System › Package Manager, then System › REST API).
- An **API key** created at **System › REST API › Keys**, tied to a user that has
  the privileges the integration needs. `WebCfg - All pages` grants everything; a
  locked-down user needs read access to system/interface/gateway/service/DHCP
  status plus write access to whatever you intend to control (firewall rules,
  aliases, services, routing).
- The API's base URL, **including its port** (the REST API commonly runs on a
  non-standard port such as `8444`, separate from the web UI).

> This integration speaks REST v2 only. pfSense installs without the REST API
> package, or older than the version it requires, are not supported.

---

## Installation

### HACS (recommended)

1. In **HACS**, open the three-dot menu → **Custom repositories**.
2. Add the repository URL and set the category to **Integration**:

   ```text
   https://github.com/nolsen311/Pfsense-REST
   ```

3. Download **pfSense Pro**, then restart Home Assistant.
4. Go to **Settings → Devices & Services → Add Integration** and search for
   **pfSense**.

### Manual

1. Download the latest release.
2. Copy the `custom_components/pfsense` folder into your Home Assistant
   `config/custom_components/` directory.
3. Restart Home Assistant and add the integration as above.

---

## Configuration

When you add the integration you are asked for:

| Field | Notes |
| --- | --- |
| **URL** | Base URL of the REST API, with scheme and port, e.g. `https://pfsense.lan:8444`. Any path is ignored. |
| **API key** | The key value from System › REST API › Keys. Sent as the `x-api-key` header. |
| **Verify SSL certificate** | Turn off for a self-signed certificate. |
| **Firewall Name** | Optional friendly name; defaults to `hostname.domain`. |

### Options

After setup, **Configure** exposes:

- **Scan Interval** – how often the main state poll runs (default 30 s).
- **Enable Device Tracker** – adds a second, slower poll of the ARP table and a
  device picker so you can track specific MAC addresses.
- **Device Tracker Scan Interval** / **Consider Home** – timing for the tracker.

---

## Entities

Most entities are created **disabled by default** — enable the specific ones you
want in the entity settings.

### Sensors

- **System:** WAN IP address, CPU usage %, CPU count, memory usage %, swap usage
  %, memory-buffer usage %, system temperature, load average (1 / 5 / 15 min).
- **DHCP:** total leases, online leases, idle/offline leases.
- **Per interface:** link status, in/out byte and packet counters (passed
  traffic) plus their kB/s and packets/s rates, interface errors, collisions.
- **Per gateway:** status, RTT delay, jitter (stddev), packet loss %.
- **Per OpenVPN server:** connected client count, total bytes in/out plus rates.
- **Per CARP virtual IP:** MASTER / BACKUP status.

### Switches

- **One per firewall rule** – toggles the rule's `disabled` flag and applies the
  change. Keyed by the pfSense internal `tracker` value.
- **One per NAT rule** (port forward and outbound) – same, keyed by the rule's
  `created_time`.
- **One per service** – start / stop a daemon (`unbound`, `haproxy`, `openvpn`,
  …).

### Binary sensor

- **CARP Status** – whether CARP is enabled and not in maintenance mode.

### Buttons

- **Reboot Router**, **Halt Router**, **Reset State Table** – one-press
  equivalents of the matching services.

### Device trackers

- One `device_tracker` per MAC address you select in the options flow, marked
  home/away from the pfSense ARP table.

### Update

- **Firmware Updates Available** – read-only. The REST API exposes no
  base-system "update available" signal or progress-tracked upgrade, so this
  entity reports status only and cannot install.

---

## Services

| Service | What it does |
| --- | --- |
| `pfsense.update_alias` | Add or remove an address from a host alias, apply the ruleset, and optionally kill matching states so the change takes effect immediately. |
| `pfsense.start_service` / `stop_service` / `restart_service` | Control a pfSense daemon by name. |
| `pfsense.set_default_gateway` | Set the IPv4 or IPv6 default gateway and apply routing. |
| `pfsense.kill_states` | Drop firewall states for a source (and optional destination). |
| `pfsense.reset_state_table` | Flush the entire state table. |
| `pfsense.send_wol` | Send a Wake-on-LAN packet from a pfSense interface. |
| `pfsense.system_reboot` / `system_halt` | Reboot or halt the firewall. |
| `pfsense.exec_command` | Run a shell command via `/api/v2/diagnostics/command_prompt` (output is truncated at 1024 characters). |

Each service is routed through an integration entity, so calls take an
`entity_id` of any pfSense entity (used only to select the target firewall).

### Example: isolate a device on a security alert

```yaml
alias: Isolate suspicious client
trigger:
  - platform: state
    entity_id: binary_sensor.perimeter_intrusion_alert
    to: "on"
action:
  - service: pfsense.update_alias
    data:
      entity_id: binary_sensor.pfsense_carp_status
      alias_name: Isolation
      address: "{{ state_attr('device_tracker.suspicious_client', 'ip') }}"
      action: add
      kill_states: true
```

### Example: route a workstation through a VPN on a schedule

```yaml
alias: Workstation VPN redirect (morning)
trigger:
  - platform: time
    at: "08:00:00"
action:
  - service: pfsense.update_alias
    data:
      entity_id: binary_sensor.pfsense_carp_status
      alias_name: vpn_clients
      address: "192.168.1.120"
      action: add
      kill_states: true
```

The alias must already be referenced by a firewall or NAT rule in pfSense; Home
Assistant only changes which addresses are in it.

---

## How it works

The integration is fully asynchronous. A `DataUpdateCoordinator` polls a set of
read-only status endpoints concurrently each cycle:

```text
GET /api/v2/status/system         CPU / memory / temperature / load / identity
GET /api/v2/status/interfaces     link state and traffic counters
GET /api/v2/status/gateways       gateway RTT / loss / status
GET /api/v2/status/openvpn/servers
GET /api/v2/status/services
GET /api/v2/status/dhcp_server/leases
GET /api/v2/status/carp
GET /api/v2/firewall/virtual_ips  CARP VIPs
GET /api/v2/firewall/rules , /nat/port_forwards , /nat/outbound/mappings
GET /api/v2/routing/gateways , /routing/gateway/default
GET /api/v2/system/dns , /system/hostname , /system/version
```

Rates (bytes/s, packets/s) are computed from consecutive polls. Successful polls
are cached to disk, so a brief pfSense outage does not blank every entity.

Writes stage a change and then call the matching apply endpoint
(`POST /api/v2/firewall/apply`, `/routing/apply`), serialised so concurrent
applies cannot race. The device's unique ID is the pfSense **Netgate device ID**
from `/api/v2/status/system`.

---

## Migrating from v2 (XML-RPC)

v3 removes the XML-RPC / `exec_php` transport entirely. On upgrade:

- **Re-authentication is required.** The stored username/password is dropped and
  Home Assistant prompts you for an API key. Entity history is preserved (the
  device unique ID is unchanged).
- **The URL must include the REST API port.**
- **Removed – no REST equivalent:** the `exec_php` service; the "Pending Notices
  Present" binary sensor and the `close_notice` / `file_notice` services.
- **`update` entity is now read-only** (no one-click firmware install).
- **Removed sensors – no REST data source:** memory byte figures
  (physmem/usermem/realmem/swap totals), CPU frequency, per-filesystem usage,
  system boot time, per-interface *blocked*-traffic counters, pf state-table
  gauges, and pfBlockerNG block counts.
- **`system_reboot`** no longer supports the `fsck` / `reroot` modes.

---

## Credits

Built on the groundwork of **Travis Hansen (@travisghansen)** and contributors to
[`travisghansen/hass-pfsense`](https://github.com/travisghansen/hass-pfsense),
and the `DonTranQuiL/pfsense-pro` fork it descends from. The REST API itself is
the community [`pfSense-pkg-RESTAPI`](https://github.com/pfrest/pfSense-pkg-RESTAPI)
project.

---

## Disclaimer

pfSense® is a registered trademark of Rubicon Communications, LLC (Netgate). This
is an independent Home Assistant integration and is not affiliated with,
endorsed by, or sponsored by Netgate.
