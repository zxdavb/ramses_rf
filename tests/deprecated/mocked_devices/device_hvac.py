#!/usr/bin/env python3
"""RAMSES RF - a RAMSES-II protocol decoder & analyser.

Mocked devices used for testing.Will provide an appropriate Tx for a given Rx.
"""

from __future__ import annotations

import logging

from ramses_tx.command import Command
from ramses_tx.const import I_, Code

from .const import __dev_mode__
from .device_heat import MockDeviceBase

DEV_MODE = __dev_mode__

FAN_ID = "32:155617"

RUNNING = True


_LOGGER = logging.getLogger(__name__)
if DEV_MODE:
    _LOGGER.setLevel(logging.DEBUG)


class MockDeviceFan(MockDeviceBase):
    """A pseudo-mocked ventilator used for testing."""

    def __init__(self, gwy, device_id, *, schema=None) -> None:
        super().__init__(gwy, device_id)

        self.fan_mode = None  # TODO: maintain internal state (is needed?)

    def rx_frame_as_cmd(self, cmd: Command) -> None:
        """Find/Create an encoded frame, and place in on the ether."""

        pkt_header = cmd.tx_header

        cmds: Command | tuple[Command] = None  # type: ignore[assignment]

        if pkt_header == f"{Code._22F1}|{I_}|{FAN_ID}":
            cmds = self.make_response_22f1()

        elif response := RESPONSES.get(pkt_header):
            cmds = self.make_response_pkt(response)

        if cmds:
            self.tx_frames_as_cmds(cmds)

    def make_response_22f1(self) -> Command:  # TODO
        return  # type: ignore[return-value]


RESPONSES: dict[str, str] = {}  # "pkt_header": "response_pkt"

"""
2022-06-01T12:12:35.694033 070  I --- 29:155617 --:------ 29:155617 22F1 003 000004                                                        # {'_mode_idx': '00', 'fan_mode': 'away',                                                           '_mode_max': '04', '_scheme': 'orcon'}
2022-06-01T12:12:35.728030 062  I 000 32:155617 --:------ 32:155617 31D9 017 000A000020202020202020202020202008                            # { 'fan_mode': '00',                        'exhaust_fan_speed': 0.000,                            'passive': True, 'damper_only': False, 'filter_dirty': False, 'frost_cycle': False, 'has_fault': False, 'flags': [0, 0, 0, 0, 1, 0, 1, 0], 'seqx_num': '000'}
2022-06-01T12:12:35.822907 062  I --- 32:155617 --:------ 32:155617 31DA 030 00EF007FFF2E2407BC08C008DA07ACF000001514140000EFEF1B5818BD00  # {                   'fan_mode': 'away',    'exhaust_fan_speed': 0.1,    'supply_fan_speed': 0.1,  'remaining_time': 0.0, 'air_quality': None, 'air_quality_base': 0, 'co2_level': None, 'indoor_humidity': 0.46, 'outdoor_humidity': 0.36, 'exhaust_temperature': 19.8, 'supply_temperature': 22.4, 'indoor_temperature': 22.66, 'outdoor_temperature': 19.64, 'speed_cap': 61440, 'bypass_position': 0.0, 'post_heat': None, 'pre_heat': None, 'supply_flow': 70.0, 'exhaust_flow': 63.33}
2022-06-01T12:12:36.304531 061  I --- 32:155617 --:------ 32:155617 31DA 030 00EF007FFF2E2407BC08C008DB07ACF00000-15-14140000EFEF1B5818BD00
2022-06-01T12:12:37.101918 062  I --- 32:155617 --:------ 32:155617 31DA 030 00EF007FFF2F2407BC08C008DB07ACF000001514140000EFEF1A5E18BD00
2022-06-01T12:12:38.757327 061  I --- 32:155617 --:------ 32:155617 31DA 030 00EF007FFF2F2407BC08C008DB07ACF000001514140000EFEF1A5E181600

2022-06-03T00:00:16.075689 067  I --- 29:155617 --:------ 29:155617 22F1 003 000104                                                        # {'_mode_idx': '01', 'fan_mode': 'low',                                                            '_mode_max': '04', '_scheme': 'orcon'}
2022-06-03T00:00:16.111006 068  I 001 32:155617 --:------ 32:155617 31D9 017 000A01FE20202020202020202020202008                            # { 'fan_mode': '01',                        'exhaust_fan_speed': 0.005,                            'passive': True, 'damper_only': False, 'filter_dirty': False, 'frost_cycle': False, 'has_fault': False, 'flags': [0, 0, 0, 0, 1, 0, 1, 0], 'seqx_num': '001'}
2022-06-03T00:00:16.218446 067  I --- 32:155617 --:------ 32:155617 31DA 030 00EF007FFF2B270636085C08A4060FF000000134460000EFEF1B3C18BD00  # {                   'fan_mode': 'speed 1', 'exhaust_fan_speed': 0.26,   'supply_fan_speed': 0.35, 'remaining_time': 0.0, 'air_quality': None, 'air_quality_base': 0, 'co2_level': None, 'indoor_humidity': 0.43, 'outdoor_humidity': 0.39, 'exhaust_temperature': 15.9, 'supply_temperature': 21.4, 'indoor_temperature': 22.12, 'outdoor_temperature': 15.51, 'speed_cap': 61440, 'bypass_position': 0.0, 'post_heat': None, 'pre_heat': None, 'supply_flow': 69.72, 'exhaust_flow': 63.33}
2022-06-03T00:00:16.430217 068  I --- 32:155617 --:------ 32:155617 31DA 030 00EF007FFF2B270636085C08A4060FF00000-01-34460000EFEF1B3C18BD00
2022-06-03T00:00:16.707640 067  I --- 32:155617 --:------ 32:155617 31DA 030 00EF007FFF2B270636085C08A4060FF000000134460000EFEF1B3C18BD00
2022-06-03T00:00:16.886867 070  I --- 32:155617 --:------ 32:155617 31DA 030 00EF007FFF2B270636085C08A4060FF000000134460000EFEF1B3C18BD00
2022-06-03T00:00:17.696060 067  I --- 32:155617 --:------ 32:155617 31DA 030 00EF007FFF2B27062C085C08A5060FF000000134460000EFEF1B3C18BD00
2022-06-03T00:00:19.366875 067  I --- 32:155617 --:------ 32:155617 31DA 030 00EF007FFF2B27062C085C08A5060FF000000134460000EFEF1A5E17DF00

2022-05-30T22:07:28.007676 074  I --- 29:155617 --:------ 29:155617 22F1 003 000204                                                        # {'_mode_idx': '02', 'fan_mode': 'medium',                                                         '_mode_max': '04', '_scheme': 'orcon'}
2022-05-30T22:07:30.984755 062  I 002 32:155617 --:------ 32:155617 31D9 017 000A020020202020202020202020202008                            # { 'fan_mode': '02',                        'exhaust_fan_speed': 0.010,                            'passive': True, 'damper_only': False, 'filter_dirty': False, 'frost_cycle': False, 'has_fault': False, 'flags': [0, 0, 0, 0, 1, 0, 1, 0], 'seqx_num': '002'}
2022-05-30T22:07:31.562695 062  I --- 32:155617 --:------ 32:155617 31DA 030 00EF007FFF262305B40820087C0589F0000002727E0000EFEF1B5818BD00  # {                   'fan_mode': 'speed 2', 'exhaust_fan_speed': 0.57,  'supply_fan_speed': 0.63,  'remaining_time': 0.0, 'air_quality': None, 'air_quality_base': 0, 'co2_level': None, 'indoor_humidity': 0.38, 'outdoor_humidity': 0.35, 'exhaust_temperature': 14.6, 'supply_temperature': 20.8, 'indoor_temperature': 21.72, 'outdoor_temperature': 14.17, 'speed_cap': 61440, 'bypass_position': 0.0, 'post_heat': None, 'pre_heat': None, 'supply_flow': 70.0, 'exhaust_flow': 63.33}
2022-05-30T22:07:31.607270 062  I --- 32:155617 --:------ 32:155617 31DA 030 00EF007FFF262305B40820087C0589F0000002727E0000EFEF1B5818BD00
2022-05-30T22:07:31.625219 062  I --- 32:155617 --:------ 32:155617 31DA 030 00EF007FFF262305B40820087B0589F0000002727E0000EFEF1B5818BD00
2022-05-30T22:07:31.639858 062  I --- 32:155617 --:------ 32:155617 31DA 030 00EF007FFF262305B40820087C0589F0000002727E0000EFEF1B5818BD00
2022-05-30T22:07:31.799649 062  I --- 32:155617 --:------ 32:155617 31DA 030 00EF007FFF262305B4082A087C0589F0000002727E0000EFEF1B5818BD00

2022-06-03T00:36:25.517455 068  I --- 29:155617 --:------ 29:155617 22F1 003 000304                                                        # {'_mode_idx': '03', 'fan_mode': 'high',                                                           '_mode_max': '04', '_scheme': 'orcon'}
2022-06-03T00:36:25.552749 067  I 003 32:155617 --:------ 32:155617 31D9 017 000A03FE20202020202020202020202008                            # { 'fan_mode': '03',                        'exhaust_fan_speed': 0.015,                            'passive': True, 'damper_only': False, 'filter_dirty': False, 'frost_cycle': False, 'has_fault': False, 'flags': [0, 0, 0, 0, 1, 0, 1, 0], 'seqx_num': '003'}
2022-06-03T00:36:25.658779 069  I --- 32:155617 --:------ 32:155617 31DA 030 00EF007FFF2B27060E0848089905FFF00000038C960000EFEF1B7318D900  # {                   'fan_mode': 'speed 3', 'exhaust_fan_speed': 0.7,   'supply_fan_speed': 0.75,  'remaining_time': 0.0, 'air_quality': None, 'air_quality_base': 0, 'co2_level': None, 'indoor_humidity': 0.43, 'outdoor_humidity': 0.39, 'exhaust_temperature': 15.5, 'supply_temperature': 21.2, 'indoor_temperature': 22.01, 'outdoor_temperature': 15.35, 'speed_cap': 61440, 'bypass_position': 0.0, 'post_heat': None, 'pre_heat': None, 'supply_flow': 70.27, 'exhaust_flow': 63.61}
2022-06-03T00:36:25.872943 068  I --- 32:155617 --:------ 32:155617 31DA 030 00EF007FFF2B27060E0848089905FFF00000038C960000EFEF1B5818D900
2022-06-03T00:36:27.138781 068  I --- 32:155617 --:------ 32:155617 31DA 030 00EF007FFF2B27060E0852089805FFF00000038C960000EFEF1B58199B00
2022-06-03T00:36:28.878103 071  I --- 32:155617 --:------ 32:155617 31DA 030 00EF007FFF2B2706180848089905FDF00000038C960000EFEF1C6D1D3000

2022-06-03T00:28:43.997557 078  I --- 29:155617 --:------ 29:155617 22F1 003 000404                                                        # {'_mode_idx': '04', 'fan_mode': 'auto',                                                           '_mode_max': '04', '_scheme': 'orcon'}
2022-06-03T00:28:44.030573 069  I 004 32:155617 --:------ 32:155617 31D9 017 003A04FE20202020202020202020202008                            # { 'fan_mode': '04',                        'exhaust_fan_speed': 0.020,                            'passive': True, 'damper_only': False, 'filter_dirty': True, 'frost_cycle': False, 'has_fault': False, 'flags': [0, 0, 1, 1, 1, 0, 1, 0], 'seqx_num': '004'}
2022-06-03T00:28:44.126979 071  I --- 32:155617 --:------ 32:155617 31DA 030 00EF007FFF2B2706180848089705FFF000225800000000EFEF01D80AF500  # {                   'fan_mode': 'auto',    'exhaust_fan_speed': 0.0,   'supply_fan_speed': 0.0,   'remaining_time': 0.0, 'air_quality': None, 'air_quality_base': 0, 'co2_level': None, 'indoor_humidity': 0.43, 'outdoor_humidity': 0.39, 'exhaust_temperature': 15.6, 'supply_temperature': 21.2, 'indoor_temperature': 21.99, 'outdoor_temperature': 15.35, 'speed_cap': 61440, 'bypass_position': 0.17, 'post_heat': None, 'pre_heat': None, 'supply_flow': 4.72, 'exhaust_flow': 28.05}
2022-06-03T00:28:44.350966 069  I --- 32:155617 --:------ 32:155617 31DA 030 00EF007FFF2B2706180848089705FFF000205800000000EFEF01D80AF500
2022-06-03T00:28:44.786142 070  I --- 32:155617 --:------ 32:155617 31DA 030 00EF007FFF2B270618084808960600F0001C5800000000EFEF01840AF500
2022-06-03T00:28:45.631553 071  I --- 32:155617 --:------ 32:155617 31DA 030 00EF007FFF2B270618084808970600F000145800000000EFEF018407D000
2022-06-03T00:28:46.742210 069  I --- 32:155617 --:------ 32:155617 31DA 030 00EF007FFF2B270618084808970602F000095800000000EFEF013107D000
2022-06-03T00:28:47.286536 069  I --- 32:155617 --:------ 32:155617 31DA 030 00EF007FFF2B270618084808970602F000045800000000EFEF013105DC00
"""
