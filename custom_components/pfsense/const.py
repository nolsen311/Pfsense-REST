"""The pfSense component."""

from __future__ import annotations

from typing import Final

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.const import (
    PERCENTAGE,
    UnitOfTemperature,
    UnitOfTime,
)

DEFAULT_USERNAME = "admin"
DOMAIN = "pfsense"

# REST API v2 auth. The pre-2.x integration used username + password over
# XML-RPC; v2 authenticates with an API key generated on the box at
# System > REST API > Keys and sent as the ``x-api-key`` header.
CONF_API_KEY = "api_key"

UNDO_UPDATE_LISTENER = "undo_update_listener"

PLATFORMS = ["sensor", "switch", "device_tracker", "binary_sensor", "update"]
LOADED_PLATFORMS = "loaded_platforms"

PFSENSE_CLIENT = "pfsense_client"
COORDINATOR = "coordinator"
DEVICE_TRACKER_COORDINATOR = "device_tracker_coordinator"
SHOULD_RELOAD = "should_reload"
TRACKED_MACS = "tracked_macs"
DEFAULT_SCAN_INTERVAL = 30
CONF_TLS_INSECURE = "tls_insecure"
DEFAULT_TLS_INSECURE = False
DEFAULT_VERIFY_SSL = True

CONF_DEVICE_TRACKER_ENABLED = "device_tracker_enabled"
DEFAULT_DEVICE_TRACKER_ENABLED = False

CONF_DEVICE_TRACKER_SCAN_INTERVAL = "device_tracker_scan_interval"
DEFAULT_DEVICE_TRACKER_SCAN_INTERVAL = 150

CONF_DEVICE_TRACKER_CONSIDER_HOME = "device_tracker_consider_home"
DEFAULT_DEVICE_TRACKER_CONSIDER_HOME = 0

CONF_DEVICES = "devices"

COUNT = "count"

BYTES_RECEIVED = "bytes_received"
BYTES_SENT = "bytes_sent"
PACKETS_RECEIVED = "packets_received"
PACKETS_SENT = "packets_sent"
DATA_PACKETS = "packets"
DATA_RATE_PACKETS_PER_SECOND = f"{DATA_PACKETS}/{UnitOfTime.SECONDS}"

ICON_MEMORY = "mdi:memory"

SENSOR_TYPES: Final[dict[str, SensorEntityDescription]] = {
    "telemetry.wan_ip": SensorEntityDescription(
        key="telemetry.wan_ip",
        name="WAN IP Address",
        icon="mdi:public",
    ),
    "telemetry.mbuf.used_percent": SensorEntityDescription(
        key="telemetry.mbuf.used_percent",
        name="Memory Buffers Used Percentage",
        native_unit_of_measurement=PERCENTAGE,
        icon=ICON_MEMORY,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    "telemetry.memory.swap_used_percent": SensorEntityDescription(
        key="telemetry.memory.swap_used_percent",
        name="Memory Swap Used Percentage",
        native_unit_of_measurement=PERCENTAGE,
        icon=ICON_MEMORY,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    "telemetry.memory.used_percent": SensorEntityDescription(
        key="telemetry.memory.used_percent",
        name="Memory Used Percentage",
        native_unit_of_measurement=PERCENTAGE,
        icon=ICON_MEMORY,
        state_class=SensorStateClass.MEASUREMENT,
    ),
    "telemetry.cpu.used_percent": SensorEntityDescription(
        key="telemetry.cpu.used_percent",
        name="CPU Usage",
        native_unit_of_measurement=PERCENTAGE,
        icon="mdi:speedometer-medium",
        state_class=SensorStateClass.MEASUREMENT,
    ),
    "telemetry.cpu.count": SensorEntityDescription(
        key="telemetry.cpu.count",
        name="CPU Count",
        native_unit_of_measurement=COUNT,
        icon="mdi:speedometer-medium",
    ),
    "telemetry.system.load_average.one_minute": SensorEntityDescription(
        key="telemetry.system.load_average.one_minute",
        name="System Load Average One Minute",
        icon="mdi:speedometer-slow",
        state_class=SensorStateClass.MEASUREMENT,
    ),
    "telemetry.system.load_average.five_minute": SensorEntityDescription(
        key="telemetry.system.load_average.five_minute",
        name="System Load Average Five Minute",
        icon="mdi:speedometer-slow",
        state_class=SensorStateClass.MEASUREMENT,
    ),
    "telemetry.system.load_average.fifteen_minute": SensorEntityDescription(
        key="telemetry.system.load_average.fifteen_minute",
        name="System Load Average Fifteen Minute",
        icon="mdi:speedometer-slow",
        state_class=SensorStateClass.MEASUREMENT,
    ),
    "telemetry.system.temp": SensorEntityDescription(
        key="telemetry.system.temp",
        name="System Temperature",
        native_unit_of_measurement=UnitOfTemperature.CELSIUS,
        device_class=SensorDeviceClass.TEMPERATURE,
        icon="mdi:thermometer",
        state_class=SensorStateClass.MEASUREMENT,
    ),
    "dhcp_stats.leases.total": SensorEntityDescription(
        key="dhcp_stats.leases.total",
        name="DHCP Leases Total",
        native_unit_of_measurement="clients",
        icon="mdi:ip-network-outline",
        state_class=SensorStateClass.MEASUREMENT,
    ),
    "dhcp_stats.leases.online": SensorEntityDescription(
        key="dhcp_stats.leases.online",
        name="DHCP Leases Online",
        native_unit_of_measurement="clients",
        icon="mdi:ip-network-outline",
        state_class=SensorStateClass.MEASUREMENT,
    ),
    "dhcp_stats.leases.idle_offline": SensorEntityDescription(
        key="dhcp_stats.leases.idle_offline",
        name="DHCP Leases Idle/Offline",
        native_unit_of_measurement="clients",
        icon="mdi:ip-network-outline",
        state_class=SensorStateClass.MEASUREMENT,
    ),
}

SERVICE_START_SERVICE = "start_service"
SERVICE_STOP_SERVICE = "stop_service"
SERVICE_RESTART_SERVICE = "restart_service"
SERVICE_RESET_STATE_TABLE = "reset_state_table"
SERVICE_KILL_STATES = "kill_states"
SERVICE_SYSTEM_HALT = "system_halt"
SERVICE_SYSTEM_REBOOT = "system_reboot"
SERVICE_SEND_WOL = "send_wol"
SERVICE_SET_DEFAULT_GATEWAY = "set_default_gateway"
SERVICE_EXEC_COMMAND = "exec_command"
