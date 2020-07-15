"""The evohome system."""

import json
import logging
from typing import Any

from .const import __dev_mode__
from .devices import Controller, Device
from .zones import Zone as EvoZone

_LOGGER = logging.getLogger(__name__)
if __dev_mode__:
    _LOGGER.setLevel(logging.DEBUG)


class EvoSystem:
    """The system class."""

    def __init__(self, gateway, controller: Controller) -> None:
        """Initialise the class."""
        # if not isinstance(controller, Controller) and not controller.is_controller:
        #     raise TypeError("Invalid controller")

        if controller.id in gateway.system_by_id:
            raise TypeError("Duplicate controller")

        self._gwy = gateway
        self.ctl = controller
        controller._evo = self  # TODO: messy?

        gateway.systems.append(self)
        gateway.system_by_id[controller.id] = self

        self.devices = []
        self.device_by_id = {}
        self.add_device(controller)

        self.zones = []
        self.zone_by_id = {}
        self.zone_by_name = {}

        self.dhw_zone = None
        self.dhw_sensor = None  # TODO: make self.dhw_zone.sensor
        self.heat_relay = None
        self._prev_code = None

    def add_device(self, device) -> Device:
        """Add a device as a child of this system."""
        # NB: sensors rarely speak directly with their controller

        if device.id not in self.device_by_id:
            self.devices.append(device)
            self.device_by_id[device.id] = device

        device.controller = self.ctl  # a setter

    def __repr__(self) -> str:
        """Return a complete representation of the system."""

        return json.dumps(self.state_db)

    def __str__(self) -> str:
        """Return a brief representation of the system."""

        return json.dumps(self.schema)

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
        """Return a representation of the system schema."""

        zone_sensors = {z.id: z.sensor for z in self.zones}
        # zone_sensors = self._zones

        return {
            "controller": self.ctl.id,
            "boiler_relay": self.heat_relay.id if self.heat_relay else None,
            "dhw_sensor": self.dhw_sensor.id if self.dhw_sensor else None,
            "zone_sensors": zone_sensors,
            # "zones": [{"00": {"sensor": None, "acuators": []}}],
            # "ufh_controllers": [],
        }

    @property
    def state_db(self) -> dict:
        """Return a representation of the internal state DB."""

        result = {}
        for evo_class in ("devices", "domains", "zones"):
            try:
                result.update({evo_class: getattr(self, f"_{evo_class}")})
            except AssertionError:
                _LOGGER.exception("Failed to produce State data")
            # except (AttributeError, LookupError, TypeError, ValueError):
            #     _LOGGER.exception("Failed to produce State data")

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

        sensor = None

        if this.code == "10A0" and this.verb == "RQ":
            if this.src.type == "07" and this.dst is self.ctl:
                # sensor = self._gwy.device_by_id[this.src.addr.id]
                sensor = this.src

        if sensor is not None:
            if self.dhw_sensor is not None:
                assert self.dhw_sensor is sensor, (self.dhw_sensor.id, sensor.id)
            else:
                self.dhw_sensor = sensor
                sensor.controller = self.ctl

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

        # note the order: most to least reliable
        heater = None

        if this.code == "3220" and this.verb == "RQ":
            if this.src is self.ctl and this.dst.type == "10":
                # heater = self._gwy.device_by_id[this.dst.addr.id]
                heater = this.dst

        elif this.code == "3EF0" and this.verb == "RQ":
            if this.src is self.ctl and this.dst.type in ("10", "13"):
                # heater = self._gwy.device_by_id[this.dst.addr.id]
                heater = this.dst

        elif this.code == "3B00" and this.verb == " I" and last is not None:
            if last.code == this.code and last.verb == this.verb:
                if this.src is self.ctl and last.src.type == "13":
                    # heater = self._gwy.device_by_id[last.src.addr.id]
                    heater = last.src

        if heater is not None:
            if self.heat_relay is not None:  # there should only be one boiler relay
                assert self.heat_relay is heater, (self.heat_relay.id, heater.id)
            else:
                self.heat_relay = heater
                heater.controller = self.ctl
                # heater.is_tpi = True

    def eavesdrop(self, this, last):
        """Use pairs of packets to learn something about the system."""

        def is_exchange():  # TODO:use is?
            return this.src is last.dst and this.dst is last.src.addr

        if self.ctl is None:
            return
        elif last is not None and last.src.controller is not None:
            if self.ctl != last.src.controller:
                return

        # if this.src.type == "01" and this.dst.controller is None:  # 3EF0
        #     this.dst.controller = this.src  # useful for TPI/OTB, uses 3EF0

        # if self.heat_relay is None and this.code in ("3220", "3B00", "3EF0"):
        if this.code in ("3220", "3B00", "3EF0"):
            self._heat_relay(this, last)

        # if self.dhw_sensor is None and this.code in ("10A0"):
        if this.code in ("10A0"):
            self._dhw_sensor(this, last)
