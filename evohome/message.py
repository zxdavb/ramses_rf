"""Evohome serial."""

from curses.ascii import isprint
from datetime import datetime as dt
from typing import Optional

from .const import (
    ALL_DEV_ID,
    COMMAND_EXPOSES_ZONE,
    COMMAND_LENGTH,
    COMMAND_LOOKUP,
    COMMAND_MAP,
    DEVICE_LOOKUP,
    DEVICE_MAP,
    HGI_DEV_ID,
    MESSAGE_FORMAT,
    MESSAGE_REGEX,
    NO_DEV_ID,
    SYSTEM_MODE_MAP,
    ZONE_MODE_MAP,
    ZONE_TYPE_MAP,
)
from .entity import (
    Bdr,
    Controller,
    Device,
    DhwSensor,
    DhwZone,
    Domain,
    RadValve,
    System,
    Thermostat,
    Trv,
    dev_hex_to_id,
)
from .logger import _LOGGER


def _update_entity(entity_id, msg, EntityClass, attrs=None):  # TODO: remove
    """Create/Update an Entity with its latest state data."""

    try:  # does the system already know about this entity?
        entity = msg._gateway.domain_by_id[entity_id]
    except KeyError:  # this is a new entity, so create it
        entity = EntityClass(entity_id, msg)
        msg._gateway.domain_by_id.update({entity_id: entity})
    if attrs is not None:
        entity.update(attrs, msg)


class Message:
    """The message class."""

    def __init__(self, packet, gateway, pkt_dt=None) -> None:
        self._packet = packet
        self._gateway = gateway
        self._pkt_dt = pkt_dt

        self.val1 = packet[0:3]  # ???
        self.type = packet[4:6]  # -I, RP, RQ, or -W
        self.val2 = packet[7:10]  # sequence number (as used by 31D9)?

        self.device_id = {}  # dev1: source (for relay_demand, is: --:------)
        self.device_type = {}  # dev2: destination of RQ, RP and -W
        self.device_number = {}  # dev3: destination of -I; for broadcasts, dev3 == dev1

        self.command_code = packet[41:45]  # .upper()  # hex

        for dev, i in enumerate(range(11, 32, 10)):
            self.device_id[dev] = packet[i : i + 9]  # noqa: E203
            self.device_number[dev] = self.device_id[dev][3:]

            self.device_type[dev] = DEVICE_MAP.get(
                self.device_id[dev][:2], f"{self.device_id[dev][:2]:>3}"
            )

        self.payload_length = int(packet[46:49])
        self.raw_payload = packet[50:]

        self._payload = None

        self._harvest()

    def _harvest(self):

        # Harvest a device for discovery
        # if self.type == "RQ" and self.device_type[0] == "HGI":
        #     pass  # either already known, or maybe a guess
        # else:
        for dev in range(3):
            if self.device_type[dev] == "HGI":
                break
            if self.device_type[dev] in [" --", "ALL"]:
                continue
            # elif self.device_type[dev] == "CTL":
            #     pass
            self._get_device(self.device_id[dev])  # create if not already exists

        # Harvest the parent zone of a device
        if self.command_code in COMMAND_EXPOSES_ZONE:
            if self.device_type[0] in [
                "STA",
                "TRV",
            ]:  # TODO: what about UFH, Elec, etc.
                device = self._gateway.device_by_id[self.device_id[0]]
                device.parent_zone = self.raw_payload[:2]
        # also for 1060, iff (TRV->)CTL
        elif self.command_code == "1060":
            if self.device_type[2] == "CTL":
                device = self._gateway.device_by_id[self.device_id[0]]
                device.parent_zone = self.raw_payload[:2]

        # Harvest zone's type - TODO: a hack
        if self.device_type[0] in ["STA", "TRV", "UFH"]:  # TODO: what about Elec/BDR
            device = self._gateway.device_by_id[self.device_id[0]]
            if device.parent_zone:
                try:
                    zone = self._gateway.domain_by_id[self.raw_payload[:2]]
                except LookupError:  # nothing to update yet
                    pass
                else:
                    zone_type = ZONE_TYPE_MAP.get(self.device_type[0])

                    if zone_type:
                        zone._type = zone_type

    def __str__(self) -> str:
        def _dev_name(idx) -> str:
            """Return a friendly device name."""
            if self.device_id[idx] == NO_DEV_ID:
                return f"{'':<10}"

            if self.device_id[idx] == ALL_DEV_ID:
                return "ALL:------"

            if idx == 2 and self.device_id[2] == self.device_id[0]:
                return ">broadcast"

            return f"{self.device_type[idx]}:{self.device_number[idx]}"

        if len(self.raw_payload) < 9:
            payload = self.raw_payload
        else:
            payload = (self.raw_payload[:5] + "...")[:9]

        message = MESSAGE_FORMAT.format(
            self.val1,
            self.type,
            "   " if self.val2 == "---" else self.val2,
            _dev_name(0),
            _dev_name(1),
            _dev_name(2),
            COMMAND_MAP.get(self.command_code, f"unknown_{self.command_code}"),
            self._packet[46:49],
            payload,
        )

        return message

    def _get_device(self, device_id):
        """Get a Device, create it if required.."""
        assert device_id not in [ALL_DEV_ID, HGI_DEV_ID, NO_DEV_ID]

        try:  # does the system already know about this entity?
            entity = self._gateway.device_by_id[device_id]
        except KeyError:  # no, this is a new entity, so create it
            DeviceClass = {
                "01": Controller,
                "04": Trv,
                "07": DhwSensor,
                "13": Bdr,
                "34": Thermostat,
            }.get(device_id[:2], Device)
            entity = DeviceClass(device_id, self._gateway)

        return entity

    def _get_zone(self, zone_idx):
        """Get a Zone, create it if required.."""
        if zone_idx != "dhw":
            assert zone_idx in ["F9", "FA", "FC"] or (0 <= int(zone_idx, 16) <= 11)

        try:  # does the system already know about this entity?
            entity = self._gateway.domain_by_id[zone_idx]
        except KeyError:  # no, this is a new entity, so create it
            if zone_idx == "dhw":
                entity = DhwZone(zone_idx, self._gateway)
            elif zone_idx in ["F9", "FA", "FC"]:
                entity = Domain(zone_idx, self._gateway)
            else:
                entity = RadValve(zone_idx, self._gateway)

        return entity

    def _update_system(self, domain_id, attrs=None):  # TODO convert to _get_xxx()
        """Create/Update a Domain with its latest state data.

        FC - central heating
        """
        assert domain_id in ["F9", "FA", "FC"]  # CH/DHW/Boiler (?), FF=??

        if not self._gateway.system:
            self._gateway.system = System("system", self._gateway)

        self._gateway.system.update(attrs if attrs else {}, self)
        return {"domain_id": domain_id, **attrs}

    @property
    def payload(self) -> dict:
        """Create a structured payload from a raw payload."""

        def device_decorator(func):
            """Docstring."""

            def wrapper(*args, **kwargs):
                if self.type == "RQ":
                    code = self.command_code  # TODO: check length for 0100
                    length = 5 if code == "0100" else 2 if code == "0016" else 1
                    assert len(args[0]) / 2 == length
                    return {self.device_id[1]: {}}

                result = func(*args, **kwargs)

                # even if result = {}, update the datetime when last seen...
                self._get_device(device_id=list(result)[0]).update(result, self)
                return result

            return wrapper

        def dhw_decorator(func):
            """Docstring."""

            def wrapper(*args, **kwargs):
                payload = args[0]
                if self.type == "RQ":
                    assert self.device_type[0] in ["DHW", "HGI"]
                    assert self.device_type[1] == "CTL"  # in ["CTL", "ALL"]
                    if self.command_code == "10A0":
                        assert len(payload) / 2 in [1, 6]  # TODO: why RQ has a payload
                    else:
                        assert len(payload) / 2 == 1
                    return

                result = func(*args, **kwargs)

                self._get_zone(zone_idx="dhw").update(result, self)
                return result

            return wrapper

        def zone_decorator(func):
            """Docstring."""

            def wrapper(*args, **kwargs):
                payload = args[0]
                if self.type == "RQ":  # seen: 0004|000A|2309, works: 12B0|2349|30C9
                    assert self.device_type[1] == "CTL"
                    assert len(payload) / 2 == 2 if self.command_code == "0004" else 1
                    return {"zone_idx": payload[:2]}

                result = func(*args, **kwargs)

                for zone in result:
                    self._get_zone(zone_idx=list(zone)[0]).update(zone, self)
                return result

            return wrapper

        def _dt(seqx) -> str:
            #      0400041C0A07E3  (...HH:MM:SS)    for sync_datetime
            #        00141B0A07E3  (...HH:MM:00)    for system_mode, zone_mode (schedules?)
            if len(seqx) == 12:
                seqx = f"00{seqx}"

            return dt(
                year=int(seqx[10:14], 16),
                month=int(seqx[8:10], 16),
                day=int(seqx[6:8], 16),
                hour=int(seqx[4:6], 16) & 0b11111,  # 1st 3 bits: DayOfWeek
                minute=int(seqx[2:4], 16),
                second=int(seqx[:2], 16),
            ).strftime("%Y-%m-%d %H:%M:%S")

        def _date(seqx) -> str:
            try:  # the seqx might be "FFFFFFFF"
                return dt(
                    year=int(seqx[4:8], 16),
                    month=int(seqx[2:4], 16),
                    day=int(seqx[:2], 16),
                ).strftime("%Y-%m-%d")
            except ValueError:
                return None

        def _dec(seqx) -> float:
            return int(seqx, 16) / 100

        def _str(seqx) -> Optional[str]:
            _string = bytearray.fromhex(seqx).decode()
            _string = "".join(_char for _char in _string if isprint(_char))
            return _string if _string else None

        def _temp(seqx) -> Optional[float]:
            return int(seqx, 16) / 100 if seqx != "7FFF" else None

        # housekeeping
        def actuator_check(payload) -> dict:  # 3B00 (TPI cycle HB/sync)
            # https://www.domoticaforum.eu/viewtopic.php?f=7&t=5806&start=105#p73681
            # TODO: alter #cycles/hour & check interval between 3B00/3EF0 changes

            assert len(payload) / 2 == 2
            assert payload[:2] in ["00", "FC"]
            assert payload[2:] == "C8"  # Could be a percentage?

            return {
                "domain_id": payload[:2],
                "actuator_check": {"00": False, "C8": True}[payload[2:]],
            }  # TODO: update domain?

        # housekeeping
        def bind_device(payload) -> dict:  # 1FC9
            assert self.type in [" I", " W"]
            assert len(payload) / 2 % 6 == 0

            cmds = []
            for i in range(0, len(payload), 12):
                cmd_code = payload[i + 2 : i + 6]
                attrs = {
                    "domain_id": payload[i : i + 2],
                    "command": COMMAND_LOOKUP.get(cmd_code, f"unknown_{cmd_code}"),
                    "device_id": dev_hex_to_id(payload[i + 6 : i + 12]),
                }
                cmds.append(attrs)
            return cmds

        @device_decorator
        def device_actuator(payload) -> dict:  # 3EF0
            assert self.type in [" I", " W", "RP"]
            assert len(payload) / 2 == 3
            assert payload in ["0000FF", "00C8FF"]

            attrs = {"actuator_enabled": {"00": False, "C8": True}[payload[2:4]]}
            return {self.device_id[0]: attrs}

        @device_decorator
        def device_battery(payload) -> dict:  # 1060
            assert self.type == " I"
            assert len(payload) / 2 == 3
            assert payload[4:6] in ["00", "01"]

            attrs = {
                "battery_level": 1 if payload[2:4] == "FF" else _dec(payload[2:4]) / 2,
                "low_battery": payload[4:6] == "00",
            }
            return {self.device_id[0]: attrs}

        @device_decorator
        def device_info(payload) -> dict:  # 10E0
            assert self.type in [" I", "RP"]
            assert len(payload) / 2 == 38

            attrs = {  # TODO: add version?
                "description": _str(payload[36:]),
                "date_2": _date(payload[28:36]),
                "date_1": _date(payload[20:28]),  # could be 'FFFFFFFF'
                "unknown_0": payload[:20],
            }
            return {self.device_id[0]: attrs}

        @dhw_decorator
        def dhw_params(payload) -> dict:  # 10A0
            assert self.type in [" I", "RP"]  # DHW sends a RQ (not an I) with payload!
            assert len(payload) / 2 == 6
            assert payload[:2] == "00"

            attrs = {
                "setpoint": _dec(payload[2:6]),  # 30.0-85.0
                "overrun": _dec(payload[6:8]),  # 0-10 (0)
                "differential": _dec(payload[8:12]),  # 1.0-10.0 (10.0)
            }
            return {"dhw": attrs}

        @dhw_decorator
        def dhw_mode(payload) -> dict:  # 1F41
            assert self.type in [" I", "RP"]
            assert len(payload) / 2 in [6, 12]
            assert payload[:2] == "00"
            assert payload[2:4] in ["00", "01"]
            assert payload[4:6] in list(ZONE_MODE_MAP)
            assert payload[6:12] == "FFFFFF"

            attrs = {
                "active": {"00": False, "01": True}[payload[2:4]],
                "mode": ZONE_MODE_MAP.get(payload[4:6]),
                "until": _dt(payload[12:24]) if payload[4:6] == "04" else None,
            }
            return {"dhw": attrs}

        # device or system
        def dhw_temp(payload) -> dict:  # 1260
            # assert len(payload) / 2 == 3  # TODO: move into subs

            @device_decorator
            def _device_dhw_temp(payload) -> dict:
                assert self.type == " I"
                attrs = {"temperature": _temp(payload[2:])}
                return {self.device_id[0]: attrs}

            @dhw_decorator
            def _system_dhw_temp(payload) -> dict:
                assert self.type == "RP"
                assert self.device_type[0] == "CTL"
                attrs = {"temperature": _temp(payload[2:])}
                return {"dhw": attrs}

            if self.device_type[0] in ["DHW"]:
                return _device_dhw_temp(payload)
            return _system_dhw_temp(payload)  # a zone (RQ/RP)

        # device, or domain (system/FC)
        def heat_demand(payload) -> dict:  # 3150 (of a device, or the FC domain)
            # event-driven, and at least every 20 mins; FC domain is highest of all TRVs
            assert self.type == " I"
            assert len(payload) / 2 == 2

            @device_decorator
            def _device_heat_demand(payload) -> dict:  # 3150
                assert self.device_type[0] == "TRV"  # TODO: also UFH, etc?
                assert 0 <= int(payload[:2], 16) <= 11  # TODO: also for Zone valves?

                attrs = {"heat_demand": _dec(payload[2:4]) / 2}
                return {self.device_id[0]: attrs}

            # @system_decorator
            def _system_heat_demand(payload) -> dict:  # 3150
                assert self.device_type[0] == "CTL"
                assert payload[:2] == "FC"  # TODO: also for Zone valves?

                attrs = {"heat_demand": _dec(payload[2:4]) / 2}
                return self._update_system(payload[:2], attrs)

            if self.device_type[0] in ["CTL"]:
                return _system_heat_demand(payload)
            return _device_heat_demand(payload)

        # @device_decorator - decorator not used as len(RQ) = 5
        def localisation(payload) -> dict:  # 0100
            assert self.type in ["RQ", "RP"]
            assert len(payload) / 2 == 5
            assert payload[:2] == "00"
            assert payload[6:] == "FFFF"

            device_id = self.device_id[0 if self.type == "RQ" else 1]
            attrs = {"language": _str(payload[2:6])}

            result = {device_id: attrs}

            # this is the end of the device_decorator
            self._get_device(device_id=list(result)[0]).update(result, self)
            return result

        # of a domain (F9, FA, FC), or zones (00-0B) with a BDR, or a device (12:xxxxxx)
        def boiler_params(payload) -> dict:  # 1100

            @device_decorator
            def _device_boiler_params(payload) -> dict:  # 1100
                assert self.type == " I"
                assert len(payload) / 2 == 5
                assert payload[2:4] in ["0C", "18", "24", "30"]
                assert payload[4:6] in ["04", "08", "0C", "10", "14"]
                assert payload[6:10] == "0400"

                attrs = {
                    "cycle_rate": int(payload[2:4], 16) / 4,  # in cycles per hour
                    "minimum_on_time": int(payload[4:6], 16) / 4,  # in minutes
                    "unknown_0": payload[6:],
                }
                return {self.device_id[2]: attrs}

            @zone_decorator
            def _zone_boiler_params(payload) -> dict:  # 1100
                # assert self.type in [" I", " W", "RQ", "RP"]
                assert len(payload) / 2 == 8
                assert payload[2:4] in ["0C", "18", "24", "30"]
                assert payload[4:6] in ["04", "08", "0C", "10", "14"]
                assert payload[6:10] == "0000"  # seen: "0400"
                assert payload[10:] == "7FFF01"

                attrs = {
                    "cycle_rate": int(payload[2:4], 16) / 4,  # in cycles per hour
                    "minimum_on_time": int(payload[4:6], 16) / 4,  # in minutes
                    "unknown_0": payload[6:10],
                    "unknown_1": payload[10:],
                }
                return [{payload[:2]: attrs}]

            if self.device_type[2] == " 12":
                return _device_boiler_params(payload)
            return _zone_boiler_params(payload)

        # of a domain (F9, FA, FC), or zones (00-0B) with a BDR, or a device (12:xxxxxx)
        def relay_demand(payload) -> dict:  # 0008
            # https://www.domoticaforum.eu/viewtopic.php?f=7&t=5806&start=105#p73681
            assert len(payload) / 2 == 2
            assert self.type == " I"

            @device_decorator
            def _device_relay_demand(payload) -> dict:  # 0008
                assert self.device_type[2] == " 12"
                # 12:227486 12:249582 12:259810, use: 0008 0009 1100 1030 2309 313F

                attrs = {"relay_demand": _dec(payload[2:4]) / 2}
                return {self.device_id[2]: attrs}

            @zone_decorator
            def _zone_relay_demand(payload) -> dict:  # 0008
                assert payload[:2] in ["F9", "FA", "FC"] or (
                    0 <= int(payload[:2], 16) <= 11
                )

                attrs = {"relay_demand": _dec(payload[2:4]) / 2}
                return [{payload[:2]: attrs}]

            if self.device_type[2] == " 12":
                return _device_relay_demand(payload)
            return _zone_relay_demand(payload)

        # of a domain (F9, FA, FC), or zones (00-0B) with a BDR, or a device (12:xxxxxx)
        def relay_failsafe(payload) -> dict:  # 0009
            # seems there can only be max one relay per domain/zone

            @device_decorator
            def _device_relay_failsafe(payload) -> dict:  # 0009
                assert self.device_type[2] == " 12"
                assert payload == "0000FF"

                failsafe = {"00": False, "01": True}.get(payload[i + 2 : i + 4])
                attrs = {"failsafe_enabled": failsafe}
                return {self.device_id[2]: attrs}

            @zone_decorator
            def _zone_relay_failsafe(payload) -> dict:  # 0009
                assert len(payload) / 2 % 3 == 0
                assert payload[:2] in ["F9", "FA", "FC"] or (
                    0 <= int(payload[:2], 16) <= 11
                )

                domains = []
                for i in range(0, len(payload), 6):
                    failsafe = {"00": False, "01": True}.get(payload[i + 2 : i + 4])
                    attrs = {"failsafe_enabled": failsafe}
                    domains.append({payload[i : i + 2]: attrs})
                return domains

            if self.device_type[2] == " 12":
                return _device_relay_failsafe(payload)
            return _zone_relay_failsafe(payload)

        # @device_decorator - decorator not used as len(RQ) = 2
        def rf_check(payload) -> dict:  # 0016 - DONE
            assert self.type in ["RQ", "RP"]
            assert len(payload) / 2 == 2
            assert payload[:2] == "00"

            # RQ from CTL: payload == "00FF"
            # RQ *to* CTL: payload == "00xx"

            if payload[2:] == "FF":
                return  # is RQ from CTL

            strength = int(payload[2:4], 16)
            attrs = {
                self.device_id[1]: {
                    "rf_signal": min(int(strength / 5) + 1, 5),
                    "rf_value": strength,
                }
            }

            result = {self.device_id[0]: attrs}

            # this is the end of the device_decorator
            self._get_device(device_id=list(result)[0]).update(result, self)
            return result

        # device or zone
        def setpoint(payload) -> dict:  # 2309 (of a device, or a zone/s)
            @device_decorator
            def _device_setpoint(payload) -> dict:  # 2309 (of a device)
                assert self.type in [" I", " W"]
                assert len(payload) / 2 == 3
                assert 0 <= int(payload[:2], 16) <= 11  # setpoint of a device

                attrs = {"setpoint": _dec(payload[2:6])}
                return {self.device_id[0]: attrs}

            @zone_decorator
            def _zone_setpoint(payload) -> dict:  # 2309 (of a zone / all zones)
                assert self.type in [" I", " W", "RP"]
                if self.type == " I":
                    assert len(payload) / 2 % 3 == 0
                else:
                    assert len(payload) / 2 == 3

                zones = []
                for i in range(0, len(payload), 6):
                    attrs = {"setpoint": _dec(payload[i + 2 : i + 6])}
                    zones.append({payload[i : i + 2]: attrs})
                return zones

            if self.device_type[0] in ["STA", "TRV"]:
                return _device_setpoint(payload)
            return _zone_setpoint(payload)  # a zone (RQ/RP), or [zones] (I)

        # housekeeping?
        def sync_cycle(payload) -> dict:  # 1F09
            # seconds until next controller cycle: TRVs (any with batteries) can sleep until then
            # the times are not universal across systems

            # cat packets.log | grep 1F09 | grep -v ' I '
            # 21:34:49.537 045 RQ --- TRV:056053 CTL:145038  --:------ 1F09 001 00
            # 21:34:49.550 045 RP --- CTL:145038 TRV:056053  --:------ 1F09 003 00 0497
            # event driven, seconds until sync

            if self.type == "RQ":
                assert len(payload) / 2 == 1
                assert payload[:2] == "00"
                return

            # cat pkts.log | grep 1F09 | grep ' 003 '
            # 11:08:48.660 054  I --- GWY:082155  --:------ >broadcast 1F09 003 00 0537
            # 11:09:11.744 045  I --- CTL:145038  --:------ >broadcast 1F09 003 FF 073F
            # periodic, seconds until sync, 0537 = 133.5 (3*89/2), 073F = 185.5 (7*53/2)

            # cat pkts.log | grep ' 1F09 003 FF' -C4
            # 11:15:22.734 045  I --- CTL:145038  --:------ CTL:145038 1F09 003 FF 073F
            # 11:15:22.760 045  I --- CTL:145038  --:------ CTL:145038 2309 024 00 076C 01 ... 02...
            # 11:15:22.781 045  I --- CTL:145038  --:------ CTL:145038 30C9 024 00 07BB 01 ... 02...
            # periodic, seconds until next sync, 073F = 185.5 (7*53/2), then 2309/C0C9

            # 19:45:19.045 045  I     CTL:145038            >broadcast 0004 022 00004... {'zone_idx': '00', 'name': 'Main Room'}
            # 19:45:19.057 045  W     CTL:145038            >broadcast 1F09 003 F80514
            # 19:45:19.067 045  I     CTL:145038            >broadcast 2309 003 0007D0   {'zone_idx': '00', 'setpoint': 20.0}

            assert len(payload) / 2 == 3
            assert payload[:2] in ["00", "F8", "FF"]

            return {
                "device_id": self.device_id[0],
                "countdown": int(payload[2:6], 16) / 10,
            }

        # housekeeping?
        def sync_datetime(payload) -> dict:  # 313F
            # https://www.automatedhome.co.uk/vbulletin/showthread.php?5085-My-HGI80-equivalent-Domoticz-setup-without-HGI80&p=36422&viewfull=1#post36422

            # 2019-11-05T04:00:05.503217 065 RQ --- TRV:189078 CTL:145038   --:------ 313F 001 00
            # 2019-11-05T04:00:05.519859 045 RP --- CTL:145038 TRV:189078   --:------ 313F 009 00FC0F0024050B07E3
            # 2019-11-05T04:00:12.712658 045 RQ --- TRV:056061 CTL:145038   --:------ 313F 001 00
            # 2019-11-05T04:00:12.728824 045 RP --- CTL:145038 TRV:056061   --:------ 313F 009 00FC160024050B07E3
            # every day at 4am TRV/RQ->CTL/RP, approx 5-10secs apart (CTL will respond at any time)

            assert payload[:2] == "00"

            if self.type == "RQ":
                assert self.device_type[0] == "TRV"  # TRV
                return

            assert len(payload) / 2 == 9
            attrs = {"datetime": _dt(payload[4:18])}
            return {"domain_id": payload[:2], **attrs}

        # @system_decorator?
        def system_mode(payload) -> dict:  # 2E04
            # if self.type == " W":

            assert len(payload) / 2 == 8
            assert payload[:2] in list(SYSTEM_MODE_MAP)  # TODO: check AutoWithReset

            attrs = {
                "mode": SYSTEM_MODE_MAP.get(payload[:2]),
                "until": _dt(payload[2:14]) if payload[14:16] != "00" else None,
            }
            return self._update_system(self.device_id[0], attrs)

        # housekeeping?
        def system_zone(payload) -> dict:  # 0005 (add/del a zone)
            # 095 RQ --- 30:082155 30:082155 07:198915 0005 055 39FF37EF7FFF7FFF7FFF7FFF0002EF18FFFF000000EF7FFF7FFFDA051002260992061002260992071001F40DACA5650501000407187940
            assert self.type in [" I"]
            if self.device_id[0] == "STA":
                assert len(payload) / 2 == 12  # or % 4?

            else:
                assert self.device_type[0] == "CTL"
                assert len(payload) / 2 == 4
                assert payload[:4] in ["0000", "000D"]  # TODO: 00=Radiator, 0D=Electri

            return {"device_id": self.device_id[0], "payload": payload}

        # device or zone
        def temperature(payload) -> dict:  # 30C9 (of a device, or a zone/s)
            @device_decorator
            def _device_temperature(payload) -> dict:  # 30C9
                assert self.type == " I"
                assert len(payload) / 2 == 3
                assert payload[:2] == "00"  # temp of a device

                attrs = {"temperature": _temp(payload[2:6])}
                return {self.device_id[0]: attrs}

            @zone_decorator
            def _zone_temperature(payload) -> dict:  # 30C9 (of a zone / all zones)
                assert self.type in [" I", "RP"]
                if self.type == " I":
                    assert len(payload) / 2 % 3 == 0
                else:
                    assert len(payload) / 2 == 3

                zones = []
                for i in range(0, len(payload), 6):
                    attrs = {"temperature": _temp(payload[i + 2 : i + 6])}
                    zones.append({payload[i : i + 2]: attrs})
                return zones

            if self.device_type[0] in ["STA", "TRV"]:
                return _device_temperature(payload)
            return _zone_temperature(payload)  # a zone (RQ/RP), or [zones] (I)

        # device or zone
        def window_state(payload) -> dict:  # 12B0 (of a device, or a zone)
            @device_decorator
            def _device_window_state(payload) -> dict:
                assert self.type == " I"
                assert len(payload) / 2 == 3
                assert payload[2:] in ["0000", "C800", "FFFF"]  # "FFFF" if N/A

                attrs = {"window_open": {"00": False, "C8": True}.get(payload[2:4])}
                return {self.device_id[0]: attrs}

            @zone_decorator
            def _zone_window_state(payload) -> dict:
                assert self.type in [" I", "RP"]
                assert self.device_type[0] == "CTL"
                assert len(payload) / 2 == 3
                assert payload[2:] in ["0000", "C800", "FFFF"]  # "FFFF" if N/A

                attrs = {"window_open": {"00": False, "C8": True}.get(payload[2:4])}
                return [{payload[:2]: attrs}]

            if self.device_type[0] == "TRV":
                return _device_window_state(payload)
            return _zone_window_state(payload)  # a zone (RQ/RP)

        @zone_decorator
        def zone_config(payload) -> dict:  # 000A (of a zone / all zones)
            def _zone_config(pkt) -> dict:
                # you cannot determine zone_type from this information
                bitmap = int(pkt[2:4], 16)
                return {
                    "min_temp": _dec(pkt[4:8]),
                    "max_temp": _dec(pkt[8:12]),
                    "flags": {
                        "local_override": not bool(bitmap & 1),
                        "openwindow_function": not bool(bitmap & 2),
                        "multi_room_mode": not bool(bitmap & 16),
                        "_bitmap": f"0b{bitmap:08b}",
                    },
                }

            assert self.type in [" I", "RP"]
            if self.type == " I":
                assert len(payload) / 2 % 6 == 0
            else:
                assert len(payload) / 2 == 6

            zones = []
            for i in range(0, len(payload), 12):
                attrs = _zone_config(payload[i : i + 12])
                zones.append({payload[i : i + 2]: attrs})
            return zones

        @zone_decorator
        def zone_mode(payload) -> dict:  # 2349 (of a zone)
            assert self.type in [" I", "RP"]
            assert len(payload) / 2 in [7, 13]
            assert payload[6:8] in list(ZONE_MODE_MAP)
            assert payload[8:14] == "FFFFFF"

            attrs = {
                "setpoint": _dec(payload[2:6]),
                "mode": ZONE_MODE_MAP.get(payload[6:8]),
                "until": _dt(payload[14:26]) if payload[6:8] == "04" else None,
            }
            return [{payload[:2]: attrs}]

        @zone_decorator
        def zone_name(payload) -> dict:  # 0004 (of a zone)
            assert self.type in [" I", "RP"]
            assert len(payload) / 2 == 22

            attrs = {"name": _str(payload[4:])}  # if == "7F" * 20, then not a zone
            return [{payload[:2]: attrs}]

        # housekeeping?
        def message_000c(payload) -> dict:  # 000C (bind schema) c.f. 1FC9
            assert self.type in [" I", " W"]
            assert len(payload) / 2 % 6 == 0

            cmds = []
            for i in range(0, len(payload), 12):
                cmd_code = payload[i + 2 : i + 6]
                attrs = {
                    "domain_id": payload[i : i + 2],
                    "command": COMMAND_LOOKUP.get(cmd_code, f"unknown_{cmd_code}"),
                    "device_id": dev_hex_to_id(payload[i + 6 : i + 12]),
                }
                cmds.append(attrs)
            return cmds

        # housekeeping?
        def message_0418(payload) -> dict:  # 0418 (ticker) - WIP
            if self.type == "RQ":
                # assert len(payload) / 2 == 3
                return

            assert len(payload) / 2 == 22
            assert payload[:2] == "00"
            assert payload[14:18] == "0000"

            attrs = {
                "domain_id": payload[:2],
                "unknown_0": payload[4:18],
                "ticker": _dec(payload[18:26]),
                "unknown_1": payload[26:38],
                "device_id": dev_hex_to_id(payload[38:]),
            }
            return {"device_id": self.device_id[0], **attrs}

        # ventilation? # @device_decorator
        def sensor_humidity(payload) -> dict:  # 12A0 (Nuaire RH sensor)
            # cat pkts.log | grep 12A0 (every 879.5s, from 168090, humidity sensor)
            # 11:05:50.027 045  I --- VNT:168090  --:------ VNT:168090 12A0 006 00 3C 07A8 049C

            assert len(payload) / 2 == 6
            assert payload[:2] == "00"  # domain?

            return {
                "domain_id": payload[:2],
                "relative_humidity": _dec(payload[2:4]),
                "temperature": _dec(payload[4:8]),
                "dewpoint": _dec(payload[8:12]),
            }

        # ventilation?
        def message_22f1(payload) -> dict:  # 22F1 (Nuaire switch)
            # cat pkts.log | grep 22F1 (event-driven, from 206250, 4-way switch)
            # 11:00:24.265 067  I --- VNT:206250 GWY:082155  --:------ 22F1 003 00 0A 0A

            assert self.type == " I"
            assert len(payload) / 2 == 3
            assert payload[:2] == "00"  # domain?
            assert payload[4:6] == "0A"

            bitmap = int(payload[2:4], 16)

            _payload = {"bitmap": bitmap}

            if bitmap in [2, 3]:
                _action = {"fan_mode": "normal" if bitmap == 2 else "boost"}
            elif bitmap in [9, 10]:
                _action = {"heater_mode": "auto" if bitmap == 10 else "off"}

            return {
                "domain_id": payload[:2],
                **_action,
                **_payload,
            }  # TODO: _update_system()?

        # ventilation?
        def message_31da(payload) -> dict:  # 31DA (Nuaire humidity)
            # cat pkts.log | grep 31DA | grep -v ' I ' (event-driven, from 168090, humidity sensor)
            # 18:37:42.848 045 RQ --- VNT:168090 GWY:082155  --:------ 31DA 001 21
            # 18:37:42.879 066 RP --- GWY:082155 VNT:168090  --:------ 31DA 029 21 EF007FFF3FEF7FFF7FFF7FFF7FFF0002EF18FFFF000000EF7FFF7FFF

            if self.type == "RQ":  # usu. VNT->GWY (when press button, followed by RP)
                assert len(payload) / 2 == 1
                assert payload[:2] == "21"  # domain?
                return

            # cat pkts.log | grep 31DA | grep ' I ' (every unit time)
            # 10:36:43.119 056  I --- GWY:082155  --:------ GWY:082155 31DA 029 21 EF007FFF3CEF7FFF7FFF7FFF7FFF0002EF18FFFF000000EF7FFF7FFF
            # 10:46:32.131 055  I --- GWY:082155  --:------ GWY:082155 31DA 029 21 EF007FFF3CEF7FFF7FFF7FFF7FFF0002EF18FFFF000000EF7FFF7FFF

            assert len(payload) / 2 == 29  # usu: I CTL-->CTL
            assert payload[:2] == "21"  # domain

            return {
                "domain_id": payload[:2],
                "relative_humidity": _dec(payload[10:12]),
                "unknown_0": payload[2:10],
                "unknown_1": payload[12:],
            }  # TODO: _update_system()?

        # ventilation?
        def message_31e0(payload) -> dict:  # 31E0 (Nuaire on/off)
            # cat pkts.log | grep 31DA | grep -v ' I ' (event-driven, from 168090, humidity sensor)
            # 11:09:49.973 045  I --- VNT:168090 GWY:082155  --:------ 31E0 004 00 00 00 00
            # 11:14:46.168 045  I --- VNT:168090 GWY:082155  --:------ 31E0 004 00 00 C8 00
            # TODO: track humidity against 00/C8

            assert len(payload) / 2 == 4  # usu: I VNT->GWY
            assert payload[:2] in "00"  # domain?
            assert payload[2:] in ["000000", "00C800"]

            return {
                "domain_id": payload[:2],
                "unknown_0": payload[2:],
            }  # TODO: _update_system()?

        # unknown
        def message_unknown(payload) -> dict:
            return

        if self._payload:
            return self._payload

        # determine which parser to use
        try:  # use locals() to get the relevant parser: e.g. zone_name()
            payload_parser = locals()[COMMAND_MAP.get(self.command_code)]
        except KeyError:
            payload_parser = message_unknown

        # use that parser
        try:
            self._payload = payload_parser(self.raw_payload) if payload_parser else None

        except AssertionError:  # for dev only?
            _LOGGER.exception("ASSERT failure, raw_packet = >>> %s <<<", self._packet)
            return None

        except (LookupError, TypeError, ValueError):
            _LOGGER.exception("EXCEPTION, raw_packet = >>> %s <<<", self._packet)
            return None

        return self._payload
