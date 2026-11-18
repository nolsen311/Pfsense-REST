# pfSense-REST

A Home Assistant integration for pfSense® firewalls. It connects through
**Netgate's built-in pfSense API** (recommended, pfSense 26.07 and newer) or the
community **REST API v2 package** (`pfSense-pkg-RESTAPI`). It surfaces live
system, interface, gateway, DHCP and VPN telemetry as entities, and lets you
drive firewall rules, NAT rules, services, aliases and routing from Home
Assistant.

> **Origin.** This project started as a fork of
> [DonTranQuiL/Pfsense-pro](https://github.com/DonTranQuiL/Pfsense-pro), but has
> since been extensively rewritten — the XML-RPC client was replaced with a
> native async REST API v2 client and most of the integration was reworked, with
> the help of Claude Cowork. It has been de-forked from the upstream repository so
> that pull requests don't get opened against DonTranQuiL/Pfsense-pro by mistake.
> It is now maintained as a standalone project.

[![Latest Release](https://img.shields.io/github/v/release/nolsen311/Pfsense-REST?style=for-the-badge&color=007ec6)](https://github.com/nolsen311/Pfsense-REST/releases)
[![License](https://img.shields.io/github/license/nolsen311/Pfsense-REST?style=for-the-badge&color=007ec6)](https://github.com/nolsen311/Pfsense-REST/blob/main/LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/nolsen311/Pfsense-REST/hass-ci.yml?branch=main&style=for-the-badge&label=CI&color=5dbb0f)](https://github.com/nolsen311/Pfsense-REST/actions/workflows/hass-ci.yml)
[![hassfest](https://img.shields.io/github/actions/workflow/status/nolsen311/Pfsense-REST/hassfest.yaml?branch=main&style=for-the-badge&label=HASSFEST&color=5dbb0f)](https://github.com/nolsen311/Pfsense-REST/actions/workflows/hassfest.yaml)
[![HACS Validation](https://img.shields.io/github/actions/workflow/status/nolsen311/Pfsense-REST/hacs.yaml?branch=main&style=for-the-badge&label=HACS&color=5dbb0f)](https://github.com/nolsen311/Pfsense-REST/actions/workflows/hacs.yaml)
[![HACS Custom](https://img.shields.io/badge/HACS-Custom-ff6e27?style=for-the-badge)](https://hacs.xyz/)

---

## Requirements

**pfSense 26.07 or newer**, and one of:

- **Netgate API (recommended).** pfSense's built-in API, served by the Netgate
  (Nexus) controller service. It is standard on every install from 26.10.
  - A pfSense user that can log in to it: a member of `admins`, or of the
    `mim_<read|modify|delete>_<role>` groups for what you want to use. Service
    control, Wake-on-LAN, state-table reset and `exec_command` also need shell
    access.
  - The API URL **with its port**, usually `https://<firewall>:8443`.
  - **A LAN pass rule from the Home Assistant host to that port.** pfSense's
    anti-lockout rule covers only the web UI port, so without this rule the
    connection just times out.
- **REST API package.** The community `pfSense-pkg-RESTAPI` v2 (System ›
  Package Manager, then System › REST API).
  - An API key from **System › REST API › Keys**, or a user for HTTP Basic or
    JWT login. The user needs read access to system, interface, gateway,
    service and DHCP status, plus write access to what you want to control.
    `WebCfg - All pages` grants everything.
  - The API URL with its port, often a non-standard one such as `8444`.

> [!WARNING]
> **The REST API package is entering end of life.** Netgate is merging pfSense
> CE and Plus from 26.10 and will remove the PHP code the package depends on
> some time after that. See
> [pfrest discussion #962](https://github.com/pfrest/pfSense-pkg-RESTAPI/discussions/962).
> New setups should use the Netgate API. To move an existing entry, see
> [Switching to the Netgate API](#switching-to-the-netgate-api).

---

## Installation

### Marketplace (Home Assistant 2026.11 and newer)

This integration is not in the HACS default catalog, so it will not show up in
a Marketplace search. Add it by link instead:

1. Go to **Settings → Marketplace**, then select **Add from link** in the
   upper-right corner.
2. Enter `https://github.com/nolsen311/Pfsense-REST`, select **Add**, then open
   **pfSense Pro** and select **Install**. Setup starts right away; no restart
   is needed.

### HACS (Home Assistant before 2026.11)

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

When you add the integration, first choose how it connects:

- **Netgate API**: enter the **URL** (e.g. `https://pfsense.lan:8443`), the
  pfSense **username** and **password**. The integration logs in and renews its
  session token itself.
- **REST API package**, with an **API key**, **username and password** (HTTP
  Basic), or **JWT**. Enter the **URL** (e.g. `https://pfsense.lan:8444`) and
  the matching credentials. Basic and JWT have to be enabled at System › REST
  API › Settings.

Both also ask for **Verify SSL certificate** (turn it off for a self-signed
certificate) and an optional **Firewall name** (defaults to `hostname.domain`).

To change the URL, credentials or API later, use **⋮ › Reconfigure** on the
entry. Entities and their history are kept.

### Options

After setup, **Configure** exposes:

- **Scan Interval**: how often the main state poll runs. The default is 30 s.
  On the Netgate API a full poll takes several seconds, so keep it at 30 s or
  more.
- **Enable Device Tracker**: adds a second, slower poll of the ARP table and a
  device picker for choosing which MAC addresses to track.
- **Device Tracker Scan Interval** / **Consider Home**: timing for the tracker.
- **Reset matching states when a rule switch is toggled**: drops existing
  connections for the rule's hosts, so the change takes effect at once.
- **Allow firmware install from Home Assistant** (Netgate API only,
  **experimental**): adds an Install button to the firmware update entity. See
  [Update](#update).

---

## Entities

Most entities are created **disabled by default** — enable the specific ones you
want in the entity settings.

### Sensors

- **System:** WAN IP address, CPU usage %, CPU count, memory usage %, swap usage
  %, memory-buffer usage %, system temperature, load average (1 / 5 / 15 min).
  On the Netgate API, CPU usage is a one-minute average, and the 5- and
  15-minute load averages are worked out from per-minute samples. Disk usage
  has no Netgate API source.
- **DHCP:** total leases, online leases, idle/offline leases.
- **State table:** current entries, usage % of the limit, and the limit. On
  the Netgate API, the entries sensor's attributes add NAT states and source
  and destination IP counts. On the REST API package the values come from
  `pfctl` through the command endpoint, which needs that privilege.
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
- **Pending Notices Present**: on while pfSense has notices waiting (the web
  UI's bell icon). The attributes give the count and the newest three. No API
  endpoint reports notices, so they're read through the shell, which needs a
  user with shell access. The sensor is unavailable without it, and once
  Netgate removes PHP from pfSense.

### Buttons

- **Reboot Router**, **Halt Router**, **Reset State Table** – one-press
  equivalents of the matching services.

### Device trackers

- One `device_tracker` per MAC address you select in the options flow, marked
  home/away from the pfSense ARP table.

### Update

- **Firmware Updates Available** shows the installed and latest pfSense
  version, plus pfSense's own status message.
  - Netgate API only. The REST API package has no source for it, so the entity
    is unavailable there.
  - The status is checked once an hour.
  - **Install is experimental and off by default.** Turn on **Allow firmware
    install from Home Assistant** in the options to get an Install button.
    The upgrade has not been verified on hardware yet, and the entity shows a
    warning saying so while the option is on.
  - The firewall reboots during the upgrade, so Home Assistant loses its
    connection until it's back. The entity shows "installing" until the new
    version is reported.

- **Package \<name\>** (Netgate API): one update entity per installed add-on
  package, showing the installed and latest version. **Install** upgrades the
  package to the latest version from pfSense's package catalog. The list is
  checked once an hour.

- **Dynamic DNS \<hostname\>** (Netgate API): the address each Dynamic DNS
  entry last registered, with the provider, interface, IPv4/IPv6 and the time
  of the last successful update as attributes. Disabled entries start
  disabled. The address comes from pfSense's update cache through the shell,
  so it needs a user with shell access. Without it the sensor has no value. It
  is read every 5 minutes. Credentials are never read into Home Assistant.

- **Certificate \<name\> Expires** (Netgate API, diagnostic): when each
  certificate expires, with `days_left`, what uses it, and the issuer as
  attributes. There's one per in-use or server certificate; ones nothing uses
  start disabled. A **Certificate expiring** repair appears when an in-use
  certificate is within 14 days of expiry, and clears itself once it's
  renewed. The list is read once an hour. Private keys are never read into
  Home Assistant.

### Health (diagnostic)

Shown under the device's **Diagnostic** section, and they stay available while
the firewall is unreachable:

- **Integration Status** – `ok`, `degraded` (some data could not be read),
  `unreachable`, `tls_error`, `auth_failed`, `privilege_missing`,
  `api_missing`, `api_error`. Attributes list which checks fail and why.
- **API Connected** – whether the latest poll got live data.
- **Last Successful Poll** – timestamp.
- **API Latency** – poll duration in ms (disabled by default).
- **Run Health Check** – button that polls immediately.

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
| `pfsense.exec_command` | Run a shell command on the firewall. On the REST API package the output is cut at 1024 characters. |

Each service is routed through an integration entity, so calls take an
`entity_id` of any pfSense entity (used only to select the target firewall).

On the Netgate API, service control, Wake-on-LAN, `reset_state_table` and
`exec_command` run through its shell endpoint, because the API has no direct
equivalent. The user therefore needs shell access.

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

The integration is fully asynchronous. A `DataUpdateCoordinator` polls the
firewall's status endpoints concurrently each cycle. A backend layer (`pypfsense`)
maps each API onto the same data, so the entities don't depend on which API you
use:

- **Netgate API** (`/api`): `/system/status`, `/system/interfaces/status`,
  `/system/gateways/status`, `/system/monitoring` (CPU, temperature, mbuf),
  `/controller/stats` (load), `/services/status`, `/services/dhcp/leases`,
  per-interface `/firewall/rules/interface/...`, `/firewall/nat/...`,
  `/services/carp/status`, `/system/update` and `/diag/arp`. Login is a
  username and password exchanged for a short-lived token, which the client
  renews.
- **REST API package** (`/api/v2`): `/status/system`, `/status/interfaces`,
  `/status/gateways`, `/status/services`, `/status/dhcp_server/leases`,
  `/firewall/rules`, `/firewall/nat/...`, `/routing/...` and `/system/...`.

Rates (bytes/s, packets/s) are computed from consecutive polls. Successful
polls are cached to disk, so a brief pfSense outage does not blank every
entity. Writes are serialised, so a change and its apply never race another
write. The device's unique ID is the pfSense **Netgate device ID**. Both APIs
report the same value, so switching APIs keeps every entity.

---

## Troubleshooting

When something stops working, look at **Settings › Repairs** first. The
integration raises a repair for each problem it can identify, and says how to
fix it. Repairs clear themselves after the next successful poll.

| Repair | Usual cause | Fix |
| --- | --- | --- |
| *pfSense is not reachable* | Firewall down, wrong URL/port, or a firewall rule blocking the HA host. | Check the URL opens from the HA host. The anti-lockout rule only covers the web GUI port; the Netgate API port (usually 8443) needs its own LAN pass rule. |
| *TLS certificate not trusted* | Self-signed certificate with **Verify SSL** on. | Install a trusted certificate, or use **⋮ › Reconfigure** to turn Verify SSL off. |
| *pfSense API not found* | Wrong port, or the API isn't running. | Netgate API: usually port 8443. REST API package: install and enable it. Include the port in the URL. |
| *missing API privileges* | The account cannot read some endpoints. Only those parts stop updating. | Grant the listed privileges in System › User Manager. |
| *API is returning errors* | Firewall-side failure. | Check the firewall's system log; open an issue with a diagnostics download. |
| *REST API package is end-of-life* | Warning only. Netgate's built-in API is running on this firewall. | [Switch to the Netgate API](#switching-to-the-netgate-api). |

Wrong credentials are handled by Home Assistant's re-authenticate prompt
rather than a repair.

**Short outages:** after a failed poll the entities keep their last values
for up to 10 minutes (or 5 scan intervals, whichever is longer). After that
they become unavailable, so old numbers are never shown as current.

**Bug reports:** attach **Settings › Devices & services › pfSense › ⋮ ›
Download diagnostics**. It contains the health state, versions and entity
counts. Credentials, the URL, IP and MAC addresses are redacted.

---

## Switching to the Netgate API

An existing REST API package entry can move to the Netgate API in place:

1. In pfSense, make sure a user can log in to the Netgate API (see
   [Requirements](#requirements)). Add a LAN pass rule from the Home Assistant
   host to the API port, usually 8443.
2. In Home Assistant, open **Settings › Devices & services › pfSense**, then
   **⋮ › Reconfigure › Netgate API**.
3. The URL is pre-filled with the same host on port 8443. Enter the username
   and password.

The integration checks that the new connection reaches the same firewall
before it changes anything. Entities, history and automations are kept, and
the old API key is removed from the entry.

Differences after switching:
- Rule switches show the correct on/off state for rules disabled in the
  pfSense web UI. The REST API package reports those as enabled.
- New switches appear for the `coredns` service and for outbound NAT rules.
- The firmware update entity becomes available.
- The disk usage sensor becomes unavailable.

---

## Migrating from v2 (XML-RPC)

v3 removes the XML-RPC / `exec_php` transport entirely. On upgrade:

- **Re-authentication is required.** The stored username/password is dropped and
  Home Assistant prompts you for an API key. Entity history is preserved (the
  device unique ID is unchanged).
- **The URL must include the REST API port.**
- **Removed – no REST equivalent:** the `exec_php` service and the
  `close_notice` / `file_notice` services. The "Pending Notices Present" binary
  sensor came back in v0.12 (read through the shell).
- **`update` entity:** no one-click firmware install on the REST API
  package. On the Netgate API it's an opt-in, experimental option.
- **Removed sensors – no REST data source:** memory byte figures
  (physmem/usermem/realmem/swap totals), CPU frequency, per-filesystem usage,
  system boot time, per-interface *blocked*-traffic counters, and pfBlockerNG
  block counts. (The pf state-table sensors came back in v0.12.)
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
