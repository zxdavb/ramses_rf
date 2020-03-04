"""Packet processor."""

import logging

# from string import printable
# import serial

from .const import MESSAGE_REGEX

_LOGGER = logging.getLogger(__name__)  # evohome.packet
_LOGGER.setLevel(logging.INFO)  # INFO or DEBUG


def is_wanted_packet(raw_packet, dtm, black_list=None) -> bool:
    """Return False if any blacklisted text is in packet."""
    if not any(x in raw_packet for x in ([] if black_list is None else black_list)):
        _LOGGER.info(
            "%s", raw_packet, extra={"date": dtm[:10], "time": dtm[11:]},
        )
        return True

    _LOGGER.debug(
        "*** Ignored packet: >>>%s<<< (is in text blacklist)",
        raw_packet,
        extra={"date": dtm[:10], "time": dtm[11:]},
    )


def is_valid_packet(raw_packet, dtm) -> bool:
    """Return True if a packet is valid."""
    if raw_packet is None:
        return False

    try:
        _ = MESSAGE_REGEX.match(raw_packet)
    except TypeError:
        _LOGGER.warning(
            "*** Invalid packet: >>>%s<<< (%s)",
            raw_packet,
            f"raw packet bad ({type(raw_packet)})",
            extra={"date": dtm[:10], "time": dtm[11:]},
        )
        return False

    else:
        if not MESSAGE_REGEX.match(raw_packet):
            err_msg = "packet structure bad"
        elif int(raw_packet[46:49]) > 48:
            err_msg = "payload too long"
        elif len(raw_packet[50:]) != 2 * int(raw_packet[46:49]):
            err_msg = "payload length mismatch"
        else:
            return True

        _LOGGER.warning(
            "*** Invalid packet: >>>%s<<< (%s)",
            raw_packet,
            err_msg,
            extra={"date": dtm[:10], "time": dtm[11:]},
        )
        return False


def is_wanted_device(raw_packet, white_list=None, black_list=None) -> bool:
    """Return True if a packet doesn't contain black-listed devices."""
    if " 18:" in raw_packet:
        return True
    if white_list:
        return any(device in raw_packet for device in white_list)
    return not any(device in raw_packet for device in black_list)
