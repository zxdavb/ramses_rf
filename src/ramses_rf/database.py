#!/usr/bin/env python3
"""RAMSES RF - Message database and index."""

from __future__ import annotations

import logging
import sqlite3
import threading
from collections import OrderedDict
from datetime import datetime as dt, timedelta as td
from typing import NewType

from .dispatcher import Message

_LOGGER = logging.getLogger(__name__)


DtmStrT = NewType("DtmStrT", str)


class MessageIndex:
    """A simple in-memory SQLite3 database for indexing messages."""

    def __init__(self) -> None:
        self._msgs: OrderedDict[DtmStrT, Message] = OrderedDict()

        self._cx = sqlite3.connect(":memory:")  # Connect to a SQLite DB in memory
        self._cu = self._cx.cursor()  # Create a cursor

        self._setup_adapter_converters()

        self._cu.execute(
            """
            CREATE TABLE messages (
                dtm    TEXT(26) NOT NULL PRIMARY KEY,
                verb   TEXT(2)  NOT NULL,
                src    TEXT(9)  NOT NULL,
                dst    TEXT(9)  NOT NULL,
                code   TEXT(4)  NOT NULL,
                ctx    TEXT     NOT NULL,
                hdr    TEXT     NOT NULL UNIQUE
            )
            """
        )

        self._cu.execute("CREATE INDEX idx_verb ON messages (verb)")
        self._cu.execute("CREATE INDEX idx_src ON messages (src)")
        self._cu.execute("CREATE INDEX idx_dst ON messages (dst)")
        self._cu.execute("CREATE INDEX idx_code ON messages (code)")
        self._cu.execute("CREATE INDEX idx_ctx ON messages (ctx)")
        self._cu.execute("CREATE INDEX idx_hdr ON messages (hdr)")

        self._cx.commit()

        self._timer = threading.Timer(3600, self._housekeeping)

        self.start()

    def __repr__(self) -> str:
        return f"MessageIndex({len(self._msgs)} messages, housekeeping={self._timer.is_alive()})"

    # def _msgs(self, device_id: DeviceIdT) -> tuple[Message, ...]:
    #     msgs = [msg for msg in self._megs.values() if msg.src.id == device_id]
    #     return msgs

    def _setup_adapter_converters(self) -> None:
        def adapt_datetime_iso(val: dt) -> str:
            """Adapt datetime.datetime to timezone-naive ISO 8601 datetime."""
            return val.isoformat(timespec="microseconds")

        sqlite3.register_adapter(dt, adapt_datetime_iso)

        def convert_datetime(val: bytes) -> dt:
            """Convert ISO 8601 datetime to datetime.datetime object."""
            return dt.fromisoformat(val.decode())

        sqlite3.register_converter("dtm", convert_datetime)

    def add(self, msg: Message) -> Message | None:
        """Add a single message to the index.

        Returns any message that was removed because it had the same header.

        Throws a warning is there is a duplicate dtm.
        """  # TODO: eventually, may be better to use SqlAlchemy

        def insert_msg(msg: Message) -> None:
            self._cu.execute(
                """
                INSERT INTO messages (dtm, verb, src, dst, code, ctx, hdr)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    msg.dtm,
                    msg.verb,
                    msg.src.id,
                    msg.dst.id,
                    msg.code,
                    msg._pkt._ctx,
                    msg._pkt._hdr,
                ),
            )

        old = self.rem(hdr=msg._pkt._hdr)

        try:  # TODO: remove, or use only when source is a packet log?
            insert_msg(msg)
        except sqlite3.IntegrityError:
            dups = self.rem(dtm=msg.dtm)
            if not dups:  # UNIQUE constraint failed: messages.dtm?
                raise
            _LOGGER.warning(
                "Overwrote dtm in index for %s: %s", msg._pkt._hdr, dups[0]._pkt
            )
            insert_msg(msg)

        dtm: DtmStrT = msg.dtm.isoformat(timespec="microseconds")  # type: ignore[assignment]
        self._msgs[dtm] = msg

        self._cx.commit()
        return old[0] if old else None

    def _rem(self, msg: Message | None = None, **kwargs: str) -> tuple[Message, ...]:
        """Remove a set of message(s) from the index."""

        msgs = self.get(msg=msg, **kwargs)

        sql = "DELETE FROM messages WHERE "
        sql += " AND ".join(f"{k} = ?" for k in kwargs)

        self._cu.execute(sql, tuple(kwargs.values()))

        for msg in msgs:
            dtm: DtmStrT = msg.dtm.isoformat(timespec="microseconds")  # type: ignore[assignment]
            self._msgs.pop(dtm)

        return msgs

    def rem(self, msg: Message | None = None, **kwargs: str) -> tuple[Message, ...]:
        """Remove a set of message(s) from the index.

        Returns any messages that were removed.
        """

        if msg and kwargs:
            raise ValueError("Either Message or kwargs should be provided, not both")
        if msg:
            kwargs["dtm"] = msg.dtm
        if not kwargs:
            raise ValueError("No Message or kwargs provided")

        msgs = self._rem(msg, **kwargs)

        self._cx.commit()
        return msgs

    def all(self, include_expired: bool = False) -> tuple[Message, ...]:
        """Return all messages from the index."""

        # self.cursor.execute("SELECT * FROM messages")
        # return [self._megs[row[0]] for row in self.cursor.fetchall()]

        return tuple(
            m for m in self._msgs.values() if include_expired or not m._expired
        )

    def get(self, msg: Message | None = None, **kwargs: str) -> tuple[Message, ...]:
        """Return a set of message(s) from the index."""

        if msg and kwargs:
            raise ValueError("Either Message or kwargs should be provided, not both")
        if msg:
            kwargs["dtm"] = msg.dtm
        if not kwargs:
            raise ValueError("No Message or kwargs provided")

        sql = "SELECT dtm FROM messages WHERE "
        sql += " AND ".join(f"{k} = ?" for k in kwargs)

        if len(self._msgs) > 8:
            pass

        return self.qry(sql, tuple(kwargs.values()))

    def qry(self, sql: str, parameters: tuple[str, ...]) -> tuple[Message, ...]:
        """Return a set of message(s) from the index, given a sql and parameters."""

        self._cu.execute(sql, parameters)
        return tuple(self._msgs[row[0]] for row in self._cu.fetchall())

    def clr(self) -> None:
        """Clear the message index (remove all messages)."""

        self._cu.execute("DELETE FROM messages")
        self._cx.commit()

        self._msgs.clear()

    def start(self) -> None:
        if not self._timer.is_alive():
            self._timer.start()
            self._timer.name = "MessageIndex.housekeeping"

    def stop(self) -> None:
        self._timer.cancel()  # stop the housekeeping thread
        # self._cx.close()  #    may still need to do queries after engine has stopped

    def _housekeeping(self) -> None:
        """Perform housekeeping on the message index.

        Remove stale messages from the index.
        """

        dtm = (dt.now() - td(days=1)).isoformat(timespec="microseconds")

        self._cu.execute("SELECT dtm FROM messages WHERE dtm < ?", (dtm,))
        for row in self._cu.fetchall():
            self._msgs.pop(row[0])

        self._cu.execute("DELETE FROM messages WHERE dtm < ?", (dtm,))
        self._cx.commit()
