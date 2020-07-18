"""Schema processor."""

import json
import logging
from typing import Tuple
import voluptuous as vol

from .const import Address, ZONE_TYPE_SLUGS, __dev_mode__
from .zones import create_zone as EvoZone

# from .zones import DhwZone, EvoZone

# false = False; null = None; true = True

DONT_CREATE_MESSAGES = 3
DONT_CREATE_ENTITIES = 2
DONT_UPDATE_ENTITIES = 1

DEVICE_ID_REGEXP = r"^[0-9]{2}:[0-9]{6}$"
DEVICE_ID = vol.Match(DEVICE_ID_REGEXP)

DOMAIN_ID_REGEXP = r"^[0-9A-F]{2}$"
DOMAIN_ID = vol.Match(DOMAIN_ID_REGEXP)

ZONE_ID_REGEXP = r"^0[0-9AB]$"
ZONE_ID = vol.Match(ZONE_ID_REGEXP)
ZONE_SCHEMA = vol.Schema(
    {
        vol.Required(ZONE_ID): vol.Any(
            None,
            {
                vol.Optional("sensor", default=None): vol.Any(None, DEVICE_ID),
                vol.Optional("devices", default=[]): vol.Any(
                    None, vol.Schema([DEVICE_ID])
                ),
                vol.Optional("type", default=None): vol.Any(
                    None, vol.Any(*list(ZONE_TYPE_SLUGS))
                ),
            },
        )
    }
)
SER2NET_SCHEMA = vol.Schema(
    {vol.Required("enabled"): bool, vol.Optional("socket", default="0.0.0.0:5000"): str}
)
CONFIG_SCHEMA = vol.Schema(
    {
        vol.Optional("disable_sending", default=True): vol.Any(None, bool),
        vol.Optional("startup_ping", default=False): vol.Any(None, bool),
        vol.Optional("use_discovery", default=False): vol.Any(None, bool),
        vol.Optional("use_schema", default=True): vol.Any(None, bool),
        vol.Optional("use_allowlist", default=True): vol.Any(None, bool),
        vol.Optional("use_blocklist", default=True): vol.Any(None, bool),
        vol.Optional("evofw_flag", default=True): vol.Any(None, bool),
        vol.Optional("ser2net_relay"): SER2NET_SCHEMA,
        vol.Optional("packet_log", default=True): vol.Any(None, bool),
    }
)
HW_SCHEMA = vol.Schema(
    {
        vol.Optional("sensor"): vol.Any(None, vol.Match(r"^07:[0-9]{6}$")),
        vol.Optional("relay"): vol.Any(None, vol.Match(r"^13:[0-9]{6}$")),
    }
)
SYSTEM_SCHEMA = vol.Schema(
    {
        vol.Required(vol.Match(r"^(01|23):[0-9]{6}$")): vol.Schema(
            {
                vol.Optional("heater_relay"): vol.Any(
                    None, vol.Match(r"^(10|13):[0-9]{6}$")
                ),
                vol.Optional("stored_hw"): vol.Any(None, HW_SCHEMA),
                vol.Optional("zones"): vol.Any(
                    None, vol.All(ZONE_SCHEMA, vol.Length(min=0, max=12))
                ),
            },
            extra=vol.ALLOW_EXTRA,
        )
    }
)
ORPHAN_SCHEMA = vol.Schema(
    {vol.Optional("orphans"): vol.Any(None, vol.All(DEVICE_ID, vol.Length(min=0)))}
)
GLOBAL_SCHEMA = vol.Any(
    vol.Any(SYSTEM_SCHEMA, vol.Length(min=0)), ORPHAN_SCHEMA, extra=vol.ALLOW_EXTRA
)
DEVICE_SCHEMA = vol.Schema(
    {
        vol.Required(DEVICE_ID): vol.Any(
            None,
            {
                vol.Optional("friendly_name", default=None): vol.Any(None, str),
                vol.Optional("_parent_zone"): vol.Any(None, DOMAIN_ID),
                vol.Optional("_has_battery"): vol.Any(None, bool),
            },
        )
    }
)
KNOWNS_SCHEMA = vol.Schema(
    {
        vol.Optional("allow_list"): vol.Any(None, vol.All(DEVICE_SCHEMA)),
        vol.Optional("block_list"): vol.Any(None, vol.All(DEVICE_SCHEMA)),
    }
)
SCHEMA = vol.Schema(
    {
        vol.Optional("configuration"): CONFIG_SCHEMA,
        vol.Optional("global_schema"): GLOBAL_SCHEMA,
        vol.Optional("known_devices"): KNOWNS_SCHEMA,
    }
)
MONITOR_SCHEMA = vol.Schema(
    {
        vol.Optional("probe_system"): vol.Any(None, str),
        vol.Optional("execut_cmd"): vol.Any(None, str),
        vol.Optional("evofw_flag"): vol.Any(None, str),
        vol.Optional("packet_log"): vol.Any(None, str),
    }
)
PARSE_SCHEMA = vol.Schema({})
CLI_SCHEMA = vol.Schema({})

_LOGGER = logging.getLogger(__name__)
if __dev_mode__:
    _LOGGER.setLevel(logging.DEBUG)


def load_config(gwy, **config) -> Tuple[dict, list, list]:
    """Process the schema, and the configuration and return True if it is valid."""

    # def proc_cli(config):
    # config["input_file"] = config.get("input_file")
    # config["known_devices"] = config.get("known_devices")
    # config["raw_output"] = config.get("raw_output", 0)

    # if self.serial_port and config["input_file"]:
    #     _LOGGER.warning(
    #         "Serial port specified (%s), so ignoring input file (%s)",
    #         self.serial_port,
    #         config["input_file"],
    #     )
    #     config["input_file"] = None

    # config["listen_only"] = not config.get("probe_system")
    # if config["input_file"]:
    #     config["listen_only"] = True

    # if config["raw_output"] >= DONT_CREATE_MESSAGES:
    #     config["message_log"] = None
    #     _stream = (None, sys.stdout)
    # else:
    #     _stream = (sys.stdout, None)

    schema_filename = config.get("config_file")

    if schema_filename is None:
        return {}, (), ()

    try:
        with open(schema_filename) as schema_fp:
            config = json.load(schema_fp)
    except FileNotFoundError:  # if it doesn't exist, create it later
        return {}, (), ()

    config = SCHEMA(config)
    params, schema = config["configuration"], config["global_schema"]
    gwy.known_devices = config["known_devices"]

    allow_list = list(config["known_devices"]["allow_list"])
    block_list = list(config["known_devices"]["block_list"])

    if params["use_allowlist"] and allow_list:
        _list = True
    elif params["use_blocklist"] and block_list:
        _list = False
    elif params["use_allowlist"] is not False and allow_list:
        _list = True
    elif params["use_blocklist"] is not False and block_list:
        _list = False
    else:
        _list = None

    if params["use_schema"]:  # regardless of filters, & updates known/allow
        (load_schema(gwy, k, v) for k, v in schema.items() if k != "orphans")

    if _list:
        allow_list += [d for d in gwy.device_by_id if d not in allow_list]
        block_list = []
    elif _list is False:
        allow_list = []
        block_list = [d for d in block_list if d not in gwy.device_by_id]
    else:
        allow_list = block_list = []  # cheeky, but OK

    return params, tuple(allow_list), tuple(block_list)


def load_schema(gwy, controller_id, schema, **kwargs) -> bool:
    """Process the schema, and the configuration and return True if it is valid."""
    # TODO: check a sensor is not a device in another zone

    ctl = Address(id=controller_id, type=controller_id[:2])
    ctl = gwy.get_device(ctl, controller=ctl)

    # gwy.evo = ctl if gwy.evo is None else gwy.evo

    if schema.get("heater_relay") is not None:
        dev = Address(id=schema["heater_relay"], type=schema["heater_relay"][:2])
        dev = gwy.get_device(dev, controller=ctl)
        gwy.evo.heater_relay = dev

    if schema.get("stored_hw") is not None:
        dhw_sensor = schema["stored_hw"].get("sensor")
        dhw_relay = schema["stored_hw"].get("relay")

        if dhw_sensor is not None:
            dev = Address(id=dhw_sensor, type=dhw_sensor[:2])
            dev = gwy.get_device(dev, controller=ctl)
            gwy.evo.dhw_sensor = dev

        if dhw_relay is not None:
            dev = Address(id=dhw_relay, type=dhw_relay[:2])
            dev = gwy.get_device(dev, controller=ctl)
            gwy.evo.dhw_relay = dev

        _ = EvoZone(gwy, ctl, "FC")  # dhw

    for ufh_ctl, ufh_schema in schema["ufh_controllers"]:
        dev = Address(id=ufh_ctl, type=ufh_ctl[:2])
        dev = gwy.get_device(ufh_ctl, controller=ctl)

    if schema.get("zones"):
        [
            EvoZone(gwy, ctl, zone_idx, zone_type=attr.get("type"))
            for zone_idx, attr in schema["zones"].items()
        ]


def load_filter(gwy, config, devices, **kwargs) -> Tuple[list, list]:
    """Process the JSON and return True if it is valid."""

    if config["known_devices"]:
        try:
            with open(config["known_devices"]) as json_file:
                devices = gwy.known_devices = json.load(json_file)
        except FileNotFoundError:  # if it doesn't exist, we'll create it later
            gwy.known_devices = {}

    if config.get("use_allowlist", bool(devices.get("allow_list"))):
        allow_list = list(devices.get("allow_list", ()))
        allow_list += [d for d in gwy.device_by_id if d not in allow_list]
        return allow_list, []

    if config.get("block_list", bool(devices.get("block_list"))):
        block_list = list(devices.get("block_list", ()))
        block_list = [d for d in block_list if d not in gwy.device_by_id]
        return [], block_list

    return [], []


# addr=gwy=ctl=evo=zon=dev=pkts=None  # noqa

# zon.add_device(addr)  # friendly name from gwy.known_devices
# evo.add_device(addr, parent_zone=None, parent_000c=None)
# gwy.add_device(addr, parent_zone=None, parent_000c=None, controller=ctl)

# dev.friendly_name = ""  # get/set
# dev.parent_zone = pkts.get("zone_idx")  # also zon.add_device()
# dev.parent_000c = ""  # get/set,          also zon.add_device()


# gwy.set_system(evo/ctl)

# gwy.add_system(ctl, tpi=None, dhw_sensor=None, dhw_relay=None, zones={})

# evo.add_zone(zone_id, zone_type=None)

# evo.set_dhw_relay(dev)
# evo.set_dhw_sensor(dev)
# evo.set_boiler(dev)

# zon.set_type(zone_type)
# zon.set_sensor(zone_type)

# dev.set_system(zone)
# dev.set_boiler(zone)
# dev.set_dhw_relay(zone)
# dev.set_dhw_sensor(zone)
# dev.set_zon_sensor(zone)
