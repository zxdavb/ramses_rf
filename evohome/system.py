"""The evohome system."""

import json
import logging
from typing import Any

from .command import __dev_mode__
from .devices import Controller, Device
from .zones import Zone as EvoZone, DhwZone

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

        self.devices = [controller]
        self.device_by_id = {controller.id: controller}
        controller._ctl = controller

        self.zones = []
        self.zone_by_id = {}
        self.zone_by_name = {}

        self._dhw = None
        self._heater_relay = None

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

    def get_zone(self, zone_id: str) -> Any:
        """Return a zone (create it if required)."""
        if zone_id in self.zone_by_id:
            return self.zone_by_id[zone_id]
        # zone_by_name = [z for z in self.zones if z.name == zone_id]
        # if len(zone_by_name):
        #     return zone_by_name[0]
        return EvoZone(self._gwy, self, zone_id)

    async def set_mode(self, mode, until=None):
        """Set the system mode for a specified duration, or indefinitely."""
        await self.ctl._async_set_mode(mode, until=until)

    async def reset_mode(self):
        """Revert the system mode to Auto."""
        await self.ctl._async_reset_mode()

    @property
    async def mode(self) -> dict:
        """Return the system mode."""
        return await self.ctl._mode

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
    def schema(self) -> dict:
        """Return the system's schema."""

        schema = {
            "heater_relay": self.heater_relay.id if self.heater_relay else None
        }  # "controller": self.ctl.id,

        stored_dhw = self.dhw.schema if self.dhw else None
        if stored_dhw:
            schema["stored_dhw"] = stored_dhw

        schema["zones"] = {z.id: z.schema for z in self.zones}

        ufh_controllers = [d.id for d in self.devices if d.type == "02"]
        if ufh_controllers:
            ufh_controllers.sort()
            schema["ufh_controllers"] = ufh_controllers

        orphans = [
            d.id
            for d in self.devices
            if d not in [self.ctl, self.heater_relay] and d._zone is None
        ]
        orphans.sort()
        schema["orphans"] = orphans

        return {self.ctl.id: schema}

    @property
    def config(self) -> dict:
        """Return the system's configuration."""

    @property
    def state(self) -> dict:
        """Return the system's current state."""

    @property
    def state_db(self) -> dict:
        """Return a representation of the internal state DB."""

        result = {}
        for evo_class in ("devices", "domains", "zones"):
            try:
                result.update(
                    {evo_class: self._entities(getattr(self, evo_class), "id")}
                )
            except AssertionError:
                _LOGGER.exception("Failed to produce State data")
            # except (AttributeError, LookupError, TypeError, ValueError):
            #     _LOGGER.exception("Failed to produce State data")

        return result

    @property
    def dhw(self) -> DhwZone:
        return self._dhw

    @dhw.setter
    def dhw(self, dhw: DhwZone) -> None:
        if not isinstance(dhw, DhwZone):
            raise ValueError

        if self._dhw is not None and self._dhw != dhw:
            raise LookupError

        if self._dhw is None:
            # self.add_device(dhw.sensor); self.add_device(dhw.relay)
            self._dhw = dhw

    @property
    def heater_relay(self) -> Device:
        return self._heater_relay

    @heater_relay.setter
    def heater_relay(self, device: Device) -> None:
        """Set the heater relay for this system (10: or 13:)."""

        if not isinstance(device, Device) or device.type not in ("10", "13"):
            raise TypeError

        if self._heater_relay is not None and self._heater_relay != device:
            raise LookupError
        # elif device.evo is not None and device.evo != self:
        #     raise LookupError  #  do this in add_devices

        if self._heater_relay is None:
            self._heater_relay = device
            self.add_device(device)

    def _eavesdrop(self, this, last):
        """Use pairs of packets to learn something about the system."""

        def is_exchange(this, last):  # TODO:use is?
            return this.src is last.dst and this.dst is last.src.addr

        def discover_heater_relay():
            """Discover the heat relay (10: or 13:) for this system.

            There's' 3 ways to find a controller's heat relay (in order of reliability):
            1.  The 3220 RQ/RP *to/from a 10:* (1x/5min)
            2a. The 3EF0 RQ/RP *to/from a 10:* (1x/1min)
            2b. The 3EF0 RQ (no RP) *to a 13:* (3x/60min)
            3.  The 3B00 I/I exchange between a CTL & a 13: (TPI cycle rate, usu. 6x/hr)

            Data from the CTL is considered 'authorative'. The 1FC9 RQ/RP exchange
            to/from a CTL is too rare to be useful.
            """

            # 18:14:14.025 066 RQ --- 01:078710 10:067219 --:------ 3220 005 0000050000
            # 18:14:14.446 065 RP --- 10:067219 01:078710 --:------ 3220 005 00C00500FF
            # 14:41:46.599 064 RQ --- 01:078710 10:067219 --:------ 3EF0 001 00
            # 14:41:46.631 063 RP --- 10:067219 01:078710 --:------ 3EF0 006 0000100000FF  # noqa

            # 06:49:03.465 045 RQ --- 01:145038 13:237335 --:------ 3EF0 001 00
            # 06:49:05.467 045 RQ --- 01:145038 13:237335 --:------ 3EF0 001 00
            # 06:49:07.468 045 RQ --- 01:145038 13:237335 --:------ 3EF0 001 00
            # 09:03:59.693 051  I --- 13:237335 --:------ 13:237335 3B00 002 00C8
            # 09:04:02.667 045  I --- 01:145038 --:------ 01:145038 3B00 002 FCC8

            # note the order: most to least reliable
            heater = None

            if this.code == "3220" and this.verb == "RQ":
                if this.src is self.ctl and this.dst.type == "10":
                    heater = this.dst

            elif this.code == "3EF0" and this.verb == "RQ":
                if this.src is self.ctl and this.dst.type in ("10", "13"):
                    heater = this.dst

            elif this.code == "3B00" and this.verb == " I" and last is not None:
                if last.code == this.code and last.verb == this.verb:
                    if this.src is self.ctl and last.src.type == "13":
                        heater = last.src

            if heater is not None:
                self.heater_relay = heater

        def discover_dhw_sensor():
            """Discover the stored HW this system (if any).

            There is only 1 way to find a controller's DHW sensor:
            1.  The 10A0 RQ/RP *from/to a 07:* (1x/4h)

            Data from the CTL is considered more authorative. The RQ is initiated by the
            DHW, so is not authorative. The I/1260 is not to/from a controller, so is
            not useful.
            """

            # 07:38:39.124 047 RQ --- 07:030741 01:102458 --:------ 10A0 006 00181F0003E4  # noqa
            # 07:38:39.140 062 RP --- 01:102458 07:030741 --:------ 10A0 006 0018380003E8  # noqa

            sensor = None

            if this.code == "10A0" and this.verb == "RP":
                if this.src is self.ctl and this.dst.type == "07":
                    sensor = this.dst

            if sensor is not None:
                if self.dhw is None:
                    self.dhw = DhwZone(self._gwy, self, "FC")
                # self.dhw.sensor = sensor

        if self.ctl is None:
            return
        elif last is not None and last.src.controller is not None:
            if self.ctl != last.src.controller:
                return

        # if this.src.type == "01" and this.dst.controller is None:  # 3EF0
        #     this.dst.controller = this.src  # useful for TPI/OTB, uses 3EF0

        # if self.heater_relay is None and this.code in ("3220", "3B00", "3EF0"):
        if this.code in ("3220", "3B00", "3EF0"):
            discover_heater_relay()

        # if self.dhw_sensor is None and this.code in ("10A0"):
        if this.code in ("10A0"):
            discover_dhw_sensor()
