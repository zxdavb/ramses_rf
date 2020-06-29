"""The evohome system."""

import json
import logging
from typing import Any, Optional

from .const import __dev_mode__
from .devices import Controller
from .domains import Zone as EvoZone

_LOGGER = logging.getLogger(__name__)
if __dev_mode__:
    _LOGGER.setLevel(logging.DEBUG)


class EvoSystem:
    """The system class."""

    def __init__(self, gateway, controller: Controller) -> None:
        """Initialise the class."""
        self._gwy = gateway
        self.ctl = controller

        gateway.systems.append(self)
        gateway.system_by_id[controller.id] = self

        self.devices = []
        self.device_by_id = {}

        self.domains = []
        self.domain_by_id = {}
        self.zones = []
        self.zone_by_id = {}
        self.zone_by_name = {}

        self.heat_relay = None
        self.dhw_sensor = None
        self._prev_code = None

    def __repr__(self) -> str:
        """Return a complete representation of the system."""

        # status, or state_db
        return json.dumps(self.state_db)

    def __str__(self) -> str:
        """Return a brief representation of the system."""

        zone_sensors = [{z.id: z.sensor} for z in self.zones]

        result = {
            "controller": self.ctl.id,
            "boiler_relay": self.heat_relay,
            "dhw_sensor": self.dhw_sensor,
            "zone_sensors": zone_sensors,
        }
        return json.dumps(result)

    def add_device(self, device, domain=None) -> None:
        """Add a device as a child of this controller."""

        if device.id not in self.device_by_id:
            self.devices.append(device)
            self.device_by_id[device.id] = device

        if domain is not None:
            domain.add_device(device)

    def get_zone(self, zone_id) -> Any:
        """Return a zone (create it if required)."""
        if zone_id in self.zone_by_id:
            return self.zone_by_id[zone_id]
        return EvoZone(self._gwy, self, zone_id)

    @staticmethod
    def _entities(entities, sort_attr) -> dict:
        """Return a dict of all entities of a class (i.e. devices, domains, or zones).

        Returns an array of entity dicts, with their public atrributes, sorted by id.
        """

        def attrs(entity) -> list:
            attr = [a for a in dir(entity) if not callable(getattr(entity, a))]
            return [a for a in attr if not a.startswith("_") and a != sort_attr]

        result = {
            getattr(e, sort_attr): {a: getattr(e, a) for a in attrs(e)}
            for e in entities
        }
        return dict(sorted(result.items()))

    @property
    def _devices(self) -> dict:
        """Return an array of device dicts, sorted by device_id."""
        return self._entities(self.devices, "id")

    @property
    def _domains(self) -> dict:
        """Return an array of domain dicts, sorted by domain_id."""
        return self._entities(self.domains, "id")

    @property
    def _zones(self) -> dict:
        """Return an array of zone dicts, sorted by zone_idx."""
        return self._entities(self.zones, "idx")

    @property
    def schema(self) -> dict:
        """Return a representation of the system."""

        schema = {
            "controller": self.ctl.id,
            "heater_relay": self.heat_relay,
            "dhw_sensor:": self.dhw_sensor,
            "zones": [{"00": {"sensor": None, "acuators": []}}],
            "ufh_controllers": [],
            "orphans": [],
        }
        return schema

    @property
    def status(self) -> Optional[dict]:
        """Return a representation of the system."""
        controllers = [d for d in self.devices if d.type == "01"]
        if len(controllers) != 1:
            _LOGGER.debug("fail test 0: more/less than 1 controller")
            return

        structure = {
            "controller": controllers[0].id,
            "boiler": {
                "dhw_sensor": controllers[0].dhw_sensor,
                "tpi_relay": controllers[0].tpi_relay,
            },
            "zones": {},
            #  "devices": {},
        }

        orphans = structure["orphans"] = [
            d.id for d in self.devices if d.parent_zone is None
        ]

        structure["heat_demand"] = {
            d.id: d.heat_demand for d in self.devices if hasattr(d, "heat_demand")
        }

        thermometers = structure["thermometers"] = {
            d.id: d.temperature for d in self.devices if hasattr(d, "temperature")
        }
        thermometers.pop(structure["boiler"]["dhw_sensor"], None)

        for z in self.zone_by_id:  # [z.idx for z in self.zones]:
            actuators = [k for d in self.data[z].get("actuators", []) for k in d.keys()]
            children = [d.id for d in self.devices if d.parent_zone == z]

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

        # for z in self.zone_by_id:  # [z.idx for z in self.zones]:
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

        for idx in structure["zones"]:
            zone = structure["zones"][idx]
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

    @property
    def state_db(self) -> dict:
        """Return a representation of the internal state DB."""

        result = {}
        for evo_class in ("devices", "domains", "zones"):
            try:
                result.update({evo_class: getattr(self, f"_{evo_class}")})
            except (AssertionError, AttributeError, LookupError, TypeError, ValueError):
                _LOGGER.exception("Failed to produce State data")

        return result

    def _dhw_sensor(self, this, last):
        """Return the id of the DHW sensor (07:) for *this* system/CTL.

        There is only 1 way to find a controller's DHW sensor:
        1.  The 10A0 RQ/RP *from/to a 07:* (1x/4h)

        Data from the CTL is considered more authorative. The RQ is initiated by the
        DHW, so is not authorative. The I/1260 is not to/from a controller, so is not
        useful.
        """

        # 07:38:39.124 047 RQ --- 07:030741 01:102458 --:------ 10A0 006 00181F0003E4
        # 07:38:39.140 062 RP --- 01:102458 07:030741 --:------ 10A0 006 0018380003E8

        result = None

        if this.code == "10A0" and this.verb == "RQ":
            if this.src.type == "07" and this.dst.addr == self.ctl.id:
                result = this.src.addr

        if result is not None:
            if self.dhw_sensor is not None:
                assert self.dhw_sensor == result
            else:
                self.dhw_sensor = result
                # self.device_by_id[result].is_dhw = True

    def _heat_relay(self, this, last):
        """Return the id of the heat relay (10: or 13:) for *this* system/CTL.

        There are 3 ways to find a controller's heat relay (in order of reliability):
        1.  The 3220 RQ/RP *to/from a 10:* (1x/5min)
        2a. The 3EF0 RQ/RP *to/from a 10:* (1x/1min)
        2b. The 3EF0 RQ (no RP) *to a 13:* (3x/60min)
        3.  The 3B00 I/I exchange between a CTL & a 13: (TPI cycle rate, usu. 6x/hr)

        Data from the CTL is considered 'authorative'. The 1FC9 RQ/RP exchange to/from a
        CTL is too rare to be useful.
        """

        # 18:14:14.025 066 RQ --- 01:078710 10:067219 --:------ 3220 005 0000050000
        # 18:14:14.446 065 RP --- 10:067219 01:078710 --:------ 3220 005 00C00500FF
        # 14:41:46.599 064 RQ --- 01:078710 10:067219 --:------ 3EF0 001 00
        # 14:41:46.631 063 RP --- 10:067219 01:078710 --:------ 3EF0 006 0000100000FF

        # 06:49:03.465 045 RQ --- 01:145038 13:237335 --:------ 3EF0 001 00
        # 06:49:05.467 045 RQ --- 01:145038 13:237335 --:------ 3EF0 001 00
        # 06:49:07.468 045 RQ --- 01:145038 13:237335 --:------ 3EF0 001 00
        # 09:03:59.693 051  I --- 13:237335 --:------ 13:237335 3B00 002 00C8
        # 09:04:02.667 045  I --- 01:145038 --:------ 01:145038 3B00 002 FCC8

        result = None

        # note the order is important (most to least reliable data)
        if this.code == "3220" and this.verb == "RQ":
            if this.src.addr == self.ctl.id and this.dst.type == "10":
                result = this.dst.addr

        elif this.code == "3EF0" and this.verb == "RQ":
            if this.src.addr == self.ctl.id and this.dst.type in ("10", "13"):
                result = this.dst.addr

        elif this.code == "3B00" and this.verb == " I" and last is not None:
            if last.code == this.code and last.verb == this.verb:
                if last.src.type == "13" and this.src.addr == self.ctl.id:
                    result = last.src.addr

        if result is not None:
            if self.heat_relay is not None:
                assert self.heat_relay == result
            else:
                self.heat_relay = result
                # self.device_by_id[result].is_tpi = True

    def eavesdrop(self, this, last):
        """Use pairs of packets to learn something about the system."""

        def is_exchange():
            return this.src.addr == last.dst.addr and this.dst.addr == last.src.addr

        if self.ctl is None:
            return

        if this.code in ("3220", "3B00", "3EF0"):
            self._heat_relay(this, last)

        if this.code in ("10A0"):
            self._dhw_sensor(this, last)
