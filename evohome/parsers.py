"""Evohome serial."""

# pylint: disable=missing-function-docstring

from datetime import datetime as dt
from datetime import timedelta
from string import printable
from typing import Optional, Union

from .const import (
    COMMAND_EXPOSES_ZONE,
    COMMAND_LENGTH,
    COMMAND_LOOKUP,
    COMMAND_MAP,
    COMMAND_SCHEMA,
    DEVICE_LOOKUP,
    DEVICE_MAP,
    DOMAIN_MAP,
    HGI_DEV_ID,
    MESSAGE_FORMAT,
    MESSAGE_REGEX,
    NON_DEV_ID,
    NUL_DEV_ID,
    SYSTEM_MODE_MAP,
    ZONE_MODE_MAP,
    ZONE_TYPE_MAP,
)
from .entity import DEVICE_CLASSES, Device, DhwZone, Domain, Zone, dev_hex_to_id
from .opentherm import OPENTHERM_MESSAGES, OPENTHERM_MSG_TYPE, ot_msg_value, parity


def parser_decorator(func):
    """WIP: Preprocess packets.

    Silently absorb anything without a parsable payload (e.g. W/RQs). Otherwise, parse
    the payload, and update the entity with the message.
    """

    def wrapper(*args, **kwargs):
        payload = args[0]
        msg = args[1]

        if msg.verb == " W":
            if msg.code in ["1100", "1F09", "1FC9", "2309"]:
                return func(*args, **kwargs)
            else:
                return

        if msg.verb != "RQ":
            return func(*args, **kwargs)

        # TODO: some RQs have a payload...

        # TRV will RQ zone_name *sans* payload...
        if msg.code in ["0004"] and msg.device_id[0][:2] == "04":  # TRV
            assert len(payload) / 2 == 2 if msg.code == "0004" else 1
            return {"zone_idx": payload[:2]}

        # THM will RQ zone_config, setpoint *with* payload...
        if msg.code in ["000A", "2309"] and len(payload) / 2 > 2:  # THM
            assert len(payload) / 2 == 6 if msg.code == "000A" else 3
            return func(*args, **kwargs)

        # STA will RQ zone_config, setpoint *sans* payload...
        if msg.code in ["000A", "2309"] and msg.device_id[0][:2] == "34":  # STA
            assert len(payload) / 2 == 1
            return {"zone_idx": payload[:2]}

        # TRV? will RQ localisation
        if msg.code == "0100":  # and msg.device_id[0][:2] == "04"  # TRV
            assert len(payload) / 2 == 5
            return func(*args, **kwargs)

        if msg.code == "0418":
            assert len(payload) / 2 == 3
            assert payload[:4] == "0000"
            assert int(payload[4:6], 16) <= 63
            return {"log_idx": payload[4:6]}
        #
        if msg.code == "10A0" and msg.device_id[0][:2] == "07":  # DHW
            return func(*args, **kwargs)

        if msg.code == "3220":  # CTL -> OTB
            return func(*args, **kwargs)

        if msg.verb == "RQ":
            # will the following break harvesting?
            if msg.code == "3EF0":
                assert payload[:2] == "00"
                return {}

            if msg.code in ["0004", "000A", "000C", "12B0", "2309", "2349", "30C9"]:
                assert int(payload[:2], 16) <= 11
                return {"zone_idx": payload[:2]}

            return {} if payload == "00" else None

        # if msg.verb == "RQ" and msg.device_id[0][:2] == "18":  # HGI
        #     return {}  # User can easily construct valid / albeit unparseable packets

        # TODO: god knows
        raise NotImplementedError

    return wrapper


def _id(seqx) -> dict:
    assert len(seqx) == 2

    if int(seqx, 16) <= 11:
        return seqx

    return DOMAIN_MAP.get(seqx, seqx)


def _dtm(seqx) -> str:
    #        00141B0A07E3  (...HH:MM:00)    for system_mode, zone_mode (schedules?)
    #      0400041C0A07E3  (...HH:MM:SS)    for sync_datetime
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


def _date(seqx) -> Optional[str]:
    try:  # the seqx might be "FFFFFFFF"
        return dt(
            year=int(seqx[4:8], 16), month=int(seqx[2:4], 16), day=int(seqx[:2], 16)
        ).strftime("%Y-%m-%d")
    except ValueError:
        return None


def _cent(seqx) -> float:
    return int(seqx, 16) / 100


def _str(seqx) -> Optional[str]:  # printable
    _string = bytearray([x for x in bytearray.fromhex(seqx) if 31 < x < 127])
    return _string.decode() if _string else None


def _temp(seqx) -> Optional[float]:
    """Temperatures are two's complement numbers."""
    if seqx == "7FFF":
        return None
    temp = int(seqx, 16)
    return (temp if temp < 2 ** 15 else temp - 2 ** 16) / 100


@parser_decorator
def parser_0001(payload, msg) -> Optional[dict]:  # rf_unknown
    # sent by a CTL before an RF_check
    # 15:12:47.769 053  W --- 01:145038 --:------ 01:145038 0001 005 FC00000505
    # 15:12:47.869 053 RQ --- 01:145038 13:237335 --:------ 0016 002 00FF
    # 15:12:47.880 053 RP --- 13:237335 01:145038 --:------ 0016 002 0017

    # sent by a THM every 5s when is signal strength test mode (0505, except 1st pkt)
    # 13:48:38.518 080  W --- 12:010740 --:------ 12:010740 0001 005 0000000501
    # 13:48:45.518 074  W --- 12:010740 --:------ 12:010740 0001 005 0000000505
    # 13:48:50.518 077  W --- 12:010740 --:------ 12:010740 0001 005 0000000505

    # sent by a HGI80 whenever its button is pressed
    # 00:22:41.540 ---  I --- --:------ --:------ --:------ 0001 005 00FFFF02FF
    # 00:22:41.757 ---  I --- --:------ --:------ --:------ 0001 005 00FFFF0200
    # 00:22:43.320 ---  I --- --:------ --:------ --:------ 0001 005 00FFFF02FF
    # 00:22:43.415 ---  I --- --:------ --:------ --:------ 0001 005 00FFFF0200

    assert len(payload) / 2 == 5
    assert payload[:2] in ["00", "FC", "FF"]
    assert payload[2:] == "00000505"
    return


@parser_decorator
def parser_0002(payload, msg) -> Optional[dict]:  # sensor_weather
    assert len(payload) / 2 == 4
    assert payload[:2] == "00"
    assert payload[6:] in ["00", "01"]

    return {"temperature": _temp(payload[2:6]), "unknown_0": payload[6:]}


@parser_decorator
def parser_0004(payload, msg) -> Optional[dict]:  # zone_name
    # appears limited to 12 characters in evohome UI
    assert len(payload) / 2 == 22
    assert int(payload[:2], 16) <= 11
    assert payload[2:4] == "00"

    return {
        "zone_idx": payload[:2],
        "name": _str(payload[4:]),
    }  # if == "7F" * 20, then not a zone


@parser_decorator
def tbd_er_0005(payload, msg) -> Optional[dict]:  # system_zone (add/del a zone?)
    assert msg.verb in [" I"]
    if msg.device_id[0][:2] == "34":  # STA
        assert len(payload) / 2 == 12  # or % 4?

    else:
        assert msg.device_id[0][:2] == "01"  # CTL
        assert len(payload) / 2 == 4
        assert payload[:4] in ["0000", "000D", "000F"]  # TODO: 00=Radiator, 0D=Electri

    return {"device_id": msg.device_id[0], "payload": payload}


@parser_decorator
def parser_0006(payload, msg) -> Optional[dict]:  # schedule_sync (any changes?)
    assert len(payload) / 2 == 4
    assert payload == "00050000"

    return {"payload": payload}


@parser_decorator
def parser_0008(payload, msg) -> Optional[dict]:  # relay_demand (domain/zone/device)
    # https://www.domoticaforum.eu/viewtopic.php?f=7&t=5806&start=105#p73681
    # e.g. Electric Heat Zone
    assert len(payload) / 2 == 2

    if payload[:2] not in ["F9", "FA", "FC"]:
        assert int(payload[:2], 16) <= 11  # TODO: when 0, when FC, when zone

    return {
        "zone_idx" if int(payload[:2], 16) <= 11 else "domain": _id(payload[:2]),
        "relay_demand": _cent(payload[2:]) / 2,
    }


@parser_decorator
def parser_0009(payload, msg) -> Optional[dict]:  # relay_failsafe
    # seems there can only be max one relay per domain/zone
    # can get: 003 or 006: FC01FF-F901FF or FC00FF-F900FF
    def _parser(seqx) -> dict:
        assert seqx[:2] in ["F9", "FC"] or (int(seqx[:2], 16) <= 11)
        assert seqx[2:4] in ["00", "01"]
        assert seqx[4:] in ["00", "FF"]

        return {
            "zone_idx" if int(seqx[:2], 16) <= 11 else "domain": _id(seqx[:2]),
            "failsafe_enabled": {"00": False, "01": True}.get(seqx[2:4]),
        }

    assert len(payload) / 2 % 3 == 0  # 003 but also 006: FC01FF-F901FF, FC00FF-F900FF
    if len(payload) / 2 == 3:
        return _parser(payload)

    return [_parser(payload[i : i + 6]) for i in range(0, len(payload), 6)]


@parser_decorator
def parser_000a(payload, msg) -> Union[dict, list, None]:  # zone_config (zone/s)
    def _parser(seqx) -> dict:
        # if seqx[2:] == "007FFF7FFF":
        #     return  # a null zones

        assert len(seqx) == 12
        assert int(seqx[:2], 16) <= 11

        # you cannot determine zone_type from this information
        bitmap = int(seqx[2:4], 16)
        return {
            "zone_idx": seqx[:2],
            "min_temp": _cent(seqx[4:8]),
            "max_temp": _cent(seqx[8:]),
            "local_override": not bool(bitmap & 1),
            "openwindow_function": not bool(bitmap & 2),
            "multi_room_mode": not bool(bitmap & 16),
            "unknown_0": f"0b{bitmap:08b}",
        }

    assert msg.verb in [" I", "RQ", "RP"]  # TODO: handle W
    if msg.verb == " I":  # the payload is an array
        assert len(payload) / 2 % 6 == 0
        return [_parser(payload[i : i + 12]) for i in range(0, len(payload), 12)]

    assert len(payload) / 2 == 6
    return _parser(payload)


@parser_decorator
def parser_000c(payload, msg) -> Optional[dict]:  # zone_actuators (not sensors)
    def _parser(seqx) -> dict:
        assert int(seqx[:2], 16) <= 11
        # assert seqx[2:4] in ["00", "0A", "0F", "10"] # usus. 00 - subzone?
        assert seqx[4:6] in ["00", "7F"]

        return {dev_hex_to_id(seqx[6:12]): seqx[4:6]}

    assert len(payload) / 2 % 6 == 0
    devices = [_parser(payload[i : i + 12]) for i in range(0, len(payload), 12)]
    return {
        "zone_idx": payload[:2],
        "actuators": [{k: v} for d in devices for k, v in d.items() if v != "7F"],
        "unknown_0": payload[2:4],
    }


@parser_decorator
def parser_000e(payload, msg) -> Optional[dict]:  # unknown
    # rarely from STA:xxxxxx
    assert len(payload) / 2 == 3
    assert payload == "000014"
    return


@parser_decorator
def parser_0016(payload, msg) -> Optional[dict]:  # rf_check
    # TODO: some RQs also contain a payload with data
    assert len(payload) / 2 == 2

    rf_value = int(payload[2:4], 16)
    return {
        "rf_check_from": msg.device_id[1],
        "rf_signal": min(int(rf_value / 5) + 1, 5),
        "rf_value": rf_value,
    }


@parser_decorator
def parser_0100(payload, msg) -> Optional[dict]:  # localisation (of device/system)
    assert len(payload) / 2 == 5  # len(RQ) = 5 too
    assert payload[:2] == "00"
    assert payload[6:] == "FFFF"

    return {
        # "device_id": msg.device_id[0 if msg.verb == "RQ" else 1],
        "language": _str(payload[2:6])
    }


@parser_decorator
def tbd_parser_0404(payload, msg) -> Optional[dict]:  # schedule - WIP
    assert len(payload) / 2 == 22
    assert payload[:2] == "00"
    return {}


FAULT_STATE = {"00": "Fault  ", "40": "Restore", "C0": "Unknown (C0)"}
FAULT_DEVICE_CLASS = {
    "00": "Controller?",
    "01": "Sensor",
    "04": "Actuator",
    "05": "DhwSensor?",
}
FAULT_TYPE = {"04": "BatteryLow", "06": "CommsFault", "0A": "SensorError"}


@parser_decorator
def parser_0418(payload, msg) -> Optional[dict]:  # system_fault
    """10 * 6 log entries in the UI, but 63 via RQs"""

    def _timestamp(seqx):
        """In the controller UI: YYYY-MM-DD HH:MM"""
        _seqx = int(seqx, 16)
        return dt(
            year=(_seqx & 0b1111111 << 24) >> 24,
            month=(_seqx & 0b1111 << 36) >> 36,
            day=(_seqx & 0b11111 << 31) >> 31,
            hour=(_seqx & 0b11111 << 19) >> 19,
            minute=(_seqx & 0b111111 << 13) >> 13,
            second=(_seqx & 0b111111 << 7) >> 7,
        ).strftime("%Y-%m-%d %H:%M:%S")

    #
    if payload == "000000B0000000000000000000007FFFFF7000000000":
        return {"log_idx": None}  # a null log entry, (or: payload[38:] == "000000")
    #
    if msg:
        assert msg.verb in [" I", "RP"]
    assert len(payload) / 2 == 22
    #
    assert payload[:2] == "00"  # unknown_0
    assert payload[2:4] in list(FAULT_STATE)  # C0 dont appear in the UI?
    assert int(payload[4:6], 16) <= 63  # TODO: upper limit is: 60? 63? more?
    assert payload[6:8] == "B0"  # unknown_1, ?priority
    assert payload[8:10] in list(FAULT_TYPE)
    assert int(payload[10:12], 16) <= 11 or payload[10:12] in ["FA"]
    assert payload[12:14] in list(FAULT_DEVICE_CLASS)
    assert payload[14:18] == "0000"  # unknown_2
    assert payload[28:30] in ["7F", "FF"]  # last bit in dt field
    assert payload[30:38] == "FFFF7000"  # unknown_3
    #
    return {
        "state": FAULT_STATE.get(payload[2:4], payload[2:4]),
        "timestamp": _timestamp(payload[18:30]),
        "fault_type": FAULT_TYPE.get(payload[8:10], payload[8:10]),
        "zone_idx" if int(payload[:2], 16) <= 11 else "domain": _id(payload[:2]),
        "device_class": FAULT_DEVICE_CLASS.get(payload[12:14], payload[12:14]),
        "device_id": dev_hex_to_id(payload[38:]),  # is "00:000001/2 for CTL?
        "log_idx": int(payload[4:6], 16),
    }


@parser_decorator
def parser_042f(payload, msg) -> Optional[dict]:  # unknown - WIP
    # 055  I --- 34:064023 --:------ 34:064023 042F 008 00000000230023F5
    # 063  I --- 34:064023 --:------ 34:064023 042F 008 00000000240024F5
    # 049  I --- 34:064023 --:------ 34:064023 042F 008 00000000250025F5
    # 045  I --- 34:064023 --:------ 34:064023 042F 008 00000000260026F5
    # 045  I --- 34:092243 --:------ 34:092243 042F 008 0000010021002201

    assert len(payload) / 2 in [8, 9]  # non-evohome are 9
    assert payload[:2] == "00"

    return {
        "counter_1": int(payload[2:6], 16),
        "counter_2": int(payload[6:10], 16),
        "counter_total": int(payload[10:14], 16),
        "unknown_0": payload[14:],
    }


@parser_decorator
def parser_1030(payload, msg) -> Optional[dict]:  # mixvalve_config (zone)
    # 01 C8-0137 C9-010F CA-0196 CB-010F CC-0101
    def _parser(seqx) -> dict:
        assert seqx[2:4] == "01"

        param_name = {
            "C8": "max_flow_temp",
            "C9": "pump_rum_time",
            "CA": "actuator_run_time",
            "CB": "min_flow_temp",
            "CC": "unknown_0",  # ?boolean?
        }[seqx[:2]]

        return {param_name: int(seqx[4:], 16)}

    assert len(payload) / 2 == 1 + 5 * 3
    assert int(payload[:2], 16) <= 11
    assert payload[30:] == "01"

    return {
        "zone_idx": payload[:2],
        **_parser(payload[2:8]),
        **_parser(payload[8:14]),
        **_parser(payload[14:20]),
        **_parser(payload[20:26]),
        **_parser(payload[26:]),
    }


@parser_decorator
def parser_1060(payload, msg) -> Optional[dict]:  # battery_state (of device)
    assert len(payload) / 2 == 3
    assert payload[4:6] in ["00", "01"]

    result = {
        "battery_level": None if payload[2:4] == "FF" else _cent(payload[2:4]) / 2,
        "low_battery": payload[4:] == "00",
    }

    if msg.device_id[0][:2] == "04" and msg.device_id[2][:2] == "01":  # TRV, CTL
        assert int(payload[:2], 16) <= 11
        result.update({"parent_zone": payload[:2]})
    else:
        assert payload[:2] == "00"

    return result


@parser_decorator
def parser_10a0(payload, msg) -> Optional[dict]:  # dhw_params
    # DHW sends a RQ (not an I) with payload!
    assert len(payload) / 2 == 6
    assert payload[:2] == "00"  # all DHW pkts have no domain

    return {
        "setpoint": _cent(payload[2:6]),  # 30.0-85.0
        "overrun": _cent(payload[6:8]),  # 0-10 (0)
        "differential": _cent(payload[8:12]),  # 1.0-10.0 (10.0)
    }


@parser_decorator
def parser_10e0(payload, msg) -> Optional[dict]:  # device_info
    assert len(payload) / 2 in [30, 38]  # a non-evohome seen with 30

    return {  # TODO: add version?
        "description": _str(payload[36:]),
        "date_1": _date(payload[20:28]),  # could be 'FFFFFFFF'
        "date_2": _date(payload[28:36]),
        "unknown_0": payload[:20],
    }


@parser_decorator
def parser_1100(payload, msg) -> Optional[dict]:  # boiler_params (domain/zone/device)
    assert len(payload) / 2 in [5, 8]
    assert payload[:2] in ["00", "FC"]
    assert payload[2:4] in ["0C", "18", "24", "30"]
    assert payload[4:6] in ["04", "08", "0C", "10", "14"]
    assert payload[6:8] in ["00", "04", "08", "0C", "10", "14"]
    assert payload[8:10] in ["00", "FF"]

    def _parser(seqx) -> dict:
        return {
            "cycle_rate": int(payload[2:4], 16) / 4,  # in cycles/hour
            "minimum_on_time": int(payload[4:6], 16) / 4,  # in minutes
            "minimum_off_time": int(payload[6:8], 16) / 4,  # in minutes
            "unknown_0": payload[8:10],  # always 00, FF?
        }

    if len(payload) / 2 == 5:
        return _parser(payload)

    assert payload[14:] == "01"
    return {
        **_parser(payload[:10]),
        "proportional_band_width": _temp(payload[10:14]),  # in degrees C
        "unknown_1": payload[14:],  # always 01?
    }


@parser_decorator
def parser_1260(payload, msg) -> Optional[dict]:  # dhw_temp
    assert len(payload) / 2 == 3
    assert payload[:2] == "00"  # all DHW pkts have no domain

    return {"temperature": _temp(payload[2:])}


@parser_decorator
def parser_1290(payload, msg) -> Optional[dict]:  # outdoor_temp
    assert len(payload) / 2 == 3
    assert payload[:2] == "00"  # no domain

    return {"temperature": _temp(payload[2:])}


@parser_decorator
def parser_12a0(payload, msg) -> Optional[dict]:  # indoor_humidity (Nuaire RH sensor)
    assert len(payload) / 2 == 6
    assert payload[:2] == "00"  # domain?

    return {
        "relative_humidity": _cent(payload[2:4]),
        "temperature": _temp(payload[4:8]),
        "dewpoint_temp": _temp(payload[8:12]),
    }


@parser_decorator
def parser_12b0(payload, msg) -> Optional[dict]:  # window_state (of a device/zone)
    assert int(payload[:2], 16) <= 11  # also for device state
    assert payload[2:] in ["0000", "C800", "FFFF"]  # "FFFF" means N/A

    return {
        "zone_idx": payload[:2],  # devices also add their zone here
        "window_open": {"00": False, "C8": True}.get(payload[2:4]),
    }


@parser_decorator
def parser_1f09(payload, msg) -> Optional[dict]:  # sync_cycle
    # TODO: Try RQ/1F09/"F8-FF" (CTL will RP to a RQ/00)
    assert len(payload) / 2 == 3
    assert payload[:2] in ["00", "F8", "FF"]  # W uses F8, non-Honeywell devices use 00

    seconds = int(payload[2:6], 16) / 10
    # TODO: delete me print(msg._timestamp)
    next_sync = dt.fromisoformat(msg._timestamp) + timedelta(seconds=seconds)

    return {
        "remaining_seconds": seconds,
        "next_sync": dt.strftime(next_sync, "%H:%M:%S"),
    }


@parser_decorator
def parser_1f41(payload, msg) -> Optional[dict]:  # dhw_mode
    assert len(payload) / 2 in [6, 12]
    assert payload[:2] == "00"  # all DHW pkts have no domain

    assert payload[2:4] in ["00", "01"]
    assert payload[4:6] in list(ZONE_MODE_MAP)
    if payload[4:6] == "04":
        assert len(payload) / 2 == 12
        assert payload[6:12] == "FFFFFF"

    return {
        "active": {"00": False, "01": True}[payload[2:4]],
        "mode": ZONE_MODE_MAP.get(payload[4:6]),
        "until": _dtm(payload[12:24]) if payload[4:6] == "04" else None,
    }


@parser_decorator
def parser_1fc9(payload, msg) -> Optional[dict]:  # bind_device
    def _parser(seqx) -> dict:
        if seqx[:2] not in ["FB", "FC"]:
            assert int(seqx[:2], 16) <= 11
        return {
            "zone_idx" if int(payload[:2], 16) <= 11 else "domain": _id(payload[:2]),
            "command": COMMAND_MAP.get(seqx[2:6], f"unknown_{seqx[2:6]}"),
            "device_id": dev_hex_to_id(seqx[6:]),
        }

    assert msg.verb in [" I", " W", "RP"]  # devices will respond to a RQ
    assert len(payload) / 2 % 6 == 0

    return [_parser(payload[i : i + 12]) for i in range(0, len(payload), 12)]


@parser_decorator
def parser_1fd4(payload, msg) -> Optional[dict]:  # opentherm_sync
    assert msg.verb in " I"
    assert len(payload) / 2 == 3
    assert payload[:2] == "00"

    return {"ticker": int(payload[2:], 16)}


@parser_decorator
def parser_22c9(payload, msg) -> Optional[dict]:  # ufh_setpoint
    def _parser(seqx) -> dict:
        assert int(seqx[:2], 16) <= 11
        assert seqx[10:] == "01"
        #
        return {
            "ufh_idx": int(seqx[:2], 16),
            "temp_low": _temp(seqx[2:6]),
            "temp_high": _temp(seqx[6:10]),
            "unknown_0": seqx[10:],
        }

    #
    assert len(payload) % 12 == 0
    return [_parser(payload[i : i + 12]) for i in range(0, len(payload), 12)]


@parser_decorator
def parser_22d9(payload, msg) -> Optional[dict]:  # opentherm_setpt
    assert len(payload) / 2 == 3
    assert payload[:2] == "00"

    return {"opentherm_setpoint": _cent(payload[2:6])}


@parser_decorator
def parser_22f1(payload, msg) -> Optional[dict]:  # ???? (Nuaire 4-way switch)
    assert len(payload) / 2 == 3
    assert payload[:2] == "00"  # domain?
    assert payload[4:6] == "0A"

    bitmap = int(payload[2:4], 16)

    _bitmap = {"_bitmap": bitmap}

    if bitmap in [2, 3]:
        _action = {"fan_mode": "normal" if bitmap == 2 else "boost"}
    elif bitmap in [9, 10]:
        _action = {"heater_mode": "auto" if bitmap == 10 else "off"}
    else:
        _action = {}

    return {**_action, **_bitmap}


@parser_decorator
def parser_2309(payload, msg) -> Union[dict, list, None]:  # setpoint (of device/zones)
    def _parser(seqx) -> dict:
        assert int(seqx[:2], 16) <= 11
        # for a TRV, '7EFF' means off
        setpoint = (
            None if seqx[2:] == "7EFF" else _cent(seqx[2:])
        )  # TODO: how to diff unknown vs off?
        return {"zone_idx": seqx[:2], "setpoint": setpoint}

    if len(payload) / 2 == 1:  # some RQs (e.g. from 12/22: to 13:) have a payload
        return

    if msg.device_id[0][:2] == "01" and msg.verb == " I":  # the payload is an array
        assert len(payload) / 2 % 3 == 0
        return [_parser(payload[i : i + 6]) for i in range(0, len(payload), 6)]

    assert len(payload) / 2 == 3

    # if msg.device_id[0] != "01" and msg.verb == " W":
    #     return

    return _parser(payload)


@parser_decorator
def parser_2349(payload, msg) -> Optional[dict]:  # zone_mode
    assert msg.verb in [" I", "RP"]
    assert len(payload) / 2 in [7, 13]
    assert payload[6:8] in list(ZONE_MODE_MAP)
    assert payload[8:14] == "FFFFFF"

    return {
        "zone_idx": payload[:2],
        "setpoint": _cent(payload[2:6]),
        "mode": ZONE_MODE_MAP.get(payload[6:8]),
        "until": _dtm(payload[14:26]) if payload[6:8] == "04" else None,
    }


@parser_decorator
def parser_2e04(payload, msg) -> Optional[dict]:  # system_mode
    # if msg.verb == " W":
    # RQ/2E04/FF

    assert len(payload) / 2 == 8
    assert payload[:2] in list(SYSTEM_MODE_MAP)  # TODO: check AutoWithReset

    return {
        "mode": SYSTEM_MODE_MAP.get(payload[:2]),
        "until": _dtm(payload[2:14]) if payload[14:] != "00" else None,
    }


@parser_decorator
def parser_30c9(payload, msg) -> Optional[dict]:  # temp (of device, zone/s)
    def _parser(seqx) -> dict:
        assert len(seqx) == 6
        assert int(seqx[:2], 16) <= 11

        return {"temperature": _temp(seqx[2:]), "zone_idx": seqx[:2]}

    if msg.device_id[0][:2] == "01" and msg.verb == " I":  # the payload is an array
        assert len(payload) / 2 % 3 == 0
        return [
            _parser(payload[i : i + 6])
            for i in range(0, len(payload), 6)
            if payload[i + 2 : i + 6] != "FFFF"
        ]

    assert len(payload) / 2 == 3

    if msg.device_id[0][:2] == "01":
        assert msg.verb == "RP"  # RP for a zone, TODO: send RQ to a device when awake
        return _parser(payload)

    return {"temperature": _temp(payload[2:])}


@parser_decorator
def parser_3120(payload, msg) -> Optional[dict]:  # unknown - WIP
    # sent by STAs every ~3:45:00, why?
    assert msg.device_id[0][:3] == "34:"
    assert len(payload) / 2 == 7
    assert payload[:2] == "00"
    assert payload == "0070B0000000FF"
    return


@parser_decorator
def parser_313f(payload, msg) -> Optional[dict]:  # sync_datetime
    # https://www.automatedhome.co.uk/vbulletin/showthread.php?5085-My-HGI80-equivalent-Domoticz-setup-without-HGI80&p=36422&viewfull=1#post36422
    # every day at ~4am TRV/RQ->CTL/RP, approx 5-10secs apart (CTL respond at any time)

    assert len(payload) / 2 == 9
    assert payload[:2] == "00"

    return {"datetime": _dtm(payload[4:18])}


@parser_decorator
def parser_3150(payload, msg) -> Optional[dict]:  # heat_demand (of device, FC domain)
    # event-driven, and periodically; FC domain is highest of all TRVs
    # TODO: all have a valid domain will UFH/CTL respond to an RQ, for FC, for a zone?

    if msg.device_id[0][:2] == "02" and payload[:2] != "FC":  # UFH
        assert len(payload) % 4 == 0  # I are arrays, sent periodically? are RPs arrays?
    else:
        assert len(payload) / 2 == 2

    if msg.device_id[0][:2] in ["01", "02", "10"]:
        assert payload[:2] == "FC" or (int(payload[:2], 16) <= 11)
    else:
        assert int(payload[:2], 16) <= 11

    return {
        "zone_idx" if int(payload[:2], 16) <= 11 else "domain": _id(payload[:2]),
        "heat_demand": _cent(payload[2:]) / 2,
    }


@parser_decorator
def parser_31da(payload, msg) -> Optional[dict]:  # UFH HCE80 (Nuaire humidity)
    assert len(payload) / 2 == 29  # usu: I CTL-->CTL
    assert payload[:2] == "21"  # domain

    return {
        "zone_idx" if int(payload[:2], 16) <= 11 else "domain": _id(payload[:2]),
        "relative_humidity": _cent(payload[10:12]),
        "unknown_0": payload[2:10],
        "unknown_1": payload[12:],
    }


@parser_decorator
def parser_31e0(payload, msg) -> Optional[dict]:  # ???? (Nuaire on/off)
    # cat pkts.log | grep 31DA | grep -v ' I ' (event-driven ex 168090, humidity sensor)
    # 11:09:49.973 045  I --- VNT:168090 GWY:082155  --:------ 31E0 004 00 00 00 00
    # 11:14:46.168 045  I --- VNT:168090 GWY:082155  --:------ 31E0 004 00 00 C8 00
    # TODO: track humidity against 00/C8, OR HEATER?

    assert len(payload) / 2 == 4  # usu: I VNT->GWY
    assert payload[:4] == "0000"  # domain?
    assert payload[4:] in ["0000", "C800"]

    return {
        "unknown_0": payload[:4],
        "state": {"00": False, "C8": True}[payload[4:6]],
        "unknown_1": payload[6:],
    }


@parser_decorator
def parser_3220(payload, msg) -> Optional[dict]:  # opentherm_msg
    assert len(payload) / 2 == 5
    assert payload[:2] == "00"

    # these are OpenTherm-specific assertions
    assert int(payload[2:4], 16) // 0x80 == parity(int(payload[2:], 16) & 0x7FFFFFFF)

    ot_msg_type = int(payload[2:4], 16) & 0x70
    assert ot_msg_type in OPENTHERM_MSG_TYPE

    assert int(payload[2:4], 16) & 0x0F == 0

    ot_msg_id = int(payload[4:6], 16)
    assert str(ot_msg_id) in OPENTHERM_MESSAGES["messages"]

    message = OPENTHERM_MESSAGES["messages"].get(str(ot_msg_id))

    result = {"id": ot_msg_id, "msg_type": OPENTHERM_MSG_TYPE[ot_msg_type]}

    if not message:
        return {**result, "value_raw": payload[6:]}

    if msg.verb == "RQ":
        assert ot_msg_type < 48
        assert payload[6:10] == "0000"
        return {
            **result,
            # "description": message["en"]
        }

    assert ot_msg_type > 48

    if isinstance(message["var"], dict):
        if isinstance(message["val"], dict):
            result["value_hb"] = ot_msg_value(
                payload[6:8], message["val"].get("hb", message["val"])
            )
            result["value_lb"] = ot_msg_value(
                payload[8:10], message["val"].get("lb", message["val"])
            )
        else:
            result["value_hb"] = ot_msg_value(payload[6:8], message["val"])
            result["value_lb"] = ot_msg_value(payload[8:10], message["val"])

    else:
        if message["val"] in ["flag8", "u8", "s8"]:
            result["value"] = ot_msg_value(payload[6:8], message["val"])
        else:
            result["value"] = ot_msg_value(payload[6:10], message["val"])

    return {
        **result,
        # "description": message["en"],
    }


@parser_decorator
def parser_3b00(payload, msg) -> Optional[dict]:  # sync_tpi (TPI cycle HB/sync)
    # https://www.domoticaforum.eu/viewtopic.php?f=7&t=5806&start=105#p73681
    # TODO: alter #cycles/hour & check interval between 3B00/3EF0 changes

    assert len(payload) / 2 == 2
    assert payload[:2] in {"01": "FC", "13": "00"}.get(msg.device_id[0][:2])
    assert payload[2:] == "C8"  # Could it be a percentage?

    return {
        "zone_idx" if int(payload[:2], 16) <= 11 else "domain": _id(payload[:2]),
        "unknown_0": {"00": False, "C8": True}.get(payload[2:]),
    }


@parser_decorator
def parser_3ef0(payload, msg) -> dict:  # actuator_enabled (state)
    if msg.device_id[0][:2] == "10":  # OTB
        assert len(payload) / 2 == 6
        assert payload[4:6] in ["10", "11"]
    else:
        assert len(payload) / 2 == 3
    assert payload[:2] == "00"  # first two characters
    assert payload[-2:] == "FF"  # last two characters

    if msg.device_id[0][:2] == "10":
        return {
            "modulation_level": _cent(payload[2:4]),
            "flame_active": {"0A": True}.get(payload[2:4], False),
            "flame_status": payload[2:4],
        }

    return {"actuator_enabled": {"00": False, "C8": True}.get(payload[2:4])}


@parser_decorator
def parser_3ef1(payload, msg) -> Optional[dict]:  # actuator_state
    assert msg.verb == "RP"
    assert len(payload) / 2 == 7
    assert payload[:2] == "00"
    assert payload[10:] in ["00FF", "C8FF"]

    return {
        "zone_idx" if int(payload[:2], 16) <= 11 else "domain": _id(payload[:2]),
        "actuator_dunno": _cent(payload[2:4]) / 2,
        "unknown_1": int(payload[2:6], 16),
        "unknown_2": int(payload[6:10], 16),
        "unknown_3": {"00": False, "C8": True}.get(payload[10:12]),
    }


@parser_decorator
def parser_unknown(payload, msg) -> None:
    # TODO: it may be useful to search payloads for hex_ids, commands, etc.
    return
