"""The evohome system."""

import logging
from typing import Optional

_LOGGER = logging.getLogger(__name__)


class EvohomeSystem:
    """The system class."""

    def __init__(self, controller_id=None) -> None:
        """Initialise the class."""
        # STATE: set the initial system state
        self.ctl_id = controller_id
        self._num_zones = None
        self._prev_code = None

        self.zones = []  # not used?
        self.zone_by_id = {}

        self.domains = []
        self.domain_by_id = {}

        self.devices = []
        self.device_by_id = {}

        self.data = {f"{i:02X}": {} for i in range(12)}

    # @property
    # def controller_id(self) -> Optional[str]:
    #     self.ctl_id

    # @controller_id.setter
    # def controller_id(self, var):
    #     self.ctl_id = var

    @property
    def _devices(self) -> Optional[dict]:
        """Calculate a system schema."""

        def attrs(device) -> list:
            return [
                attr
                for attr in dir(device)
                if not attr.startswith("_") and not callable(getattr(device, attr))
            ]

        return {d.device_id: {a: getattr(d, a) for a in attrs(d)} for d in self.devices}

    @property
    def status(self) -> Optional[dict]:
        """Calculate a system schema."""
        controllers = [d for d in self.devices if d.device_type == "CTL"]
        if len(controllers) != 1:
            _LOGGER.debug("fail test 0: more/less than 1 controller")
            return

        structure = {
            "controller": controllers[0].device_id,
            "boiler": {
                "dhw_sensor": controllers[0].dhw_sensor,
                "tpi_relay": controllers[0].tpi_relay,
            },
            "zones": {},
            #  "devices": {},
        }

        orphans = structure["orphans"] = [
            d.device_id for d in self.devices if d.parent_zone is None
        ]

        structure["heat_demand"] = {
            d.device_id: d.heat_demand
            for d in self.devices
            if hasattr(d, "heat_demand")
        }

        thermometers = structure["thermometers"] = {
            d.device_id: d.temperature
            for d in self.devices
            if hasattr(d, "temperature")
        }
        thermometers.pop(structure["boiler"]["dhw_sensor"], None)

        for z in self.zone_by_id:  # [z.zone_idx for z in self.zones]:
            actuators = [k for d in self.data[z].get("actuators", []) for k in d.keys()]
            children = [d.device_id for d in self.devices if d.parent_zone == z]

            zone = structure["zones"][z] = {
                "name": self.data[z].get("name"),  # TODO: do it this way
                "temperature": self.zone_by_id[z].temperature,  # TODO: or this way
                "heat_demand": self.zone_by_id[z].heat_demand,
                "sensor": None,
                "actuators": actuators,
                "children": children,  # TODO: could this include non-actuators?
                "devices": list(set(actuators) | set(children)),
            }
            orphans = list(set(orphans) - set(zone["devices"]))

        # check each zones has a unique (and non-null) temperature
        zone_map = {
            str(v["temperature"]): k
            for k, v in structure["zones"].items()
            if v["temperature"] is not None
        }

        structure["orphans"] = orphans

        # for z in self.zone_by_id:  # [z.zone_idx for z in self.zones]:
        #     if

        # TODO: needed? or just process only those with a unique temp?
        if len(zone_map) != len(structure["zones"]):  # duplicate/null temps
            _LOGGER.debug("fail test 1: non-unique (null) zone temps")
            return structure

        # check all possible sensors have a unique temp - how?
        temp_map = [t for t in thermometers.values() if t is not None]
        if len(temp_map) != len(thermometers):  # duplicate/null temps
            _LOGGER.debug("fail test 2: null device temps")
            return structure

        temp_map = {str(v): k for k, v in thermometers.items() if v is not None}

        for zone_idx in structure["zones"]:
            zone = structure["zones"][zone_idx]
            sensor = temp_map.get(str(zone["temperature"]))
            if sensor:
                zone["sensor"] = sensor
                if sensor in structure["orphans"]:
                    structure["orphans"].remove(sensor)
                orphans = list(set(orphans) - set(sensor))

                # TODO: max 1 remaining zone without a sensor
                # if len(thermometers) == 0:
                # structure.pop("thermometers")

                structure["orphans"] = orphans

        return structure
