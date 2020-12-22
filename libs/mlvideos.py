#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import logging
from contextlib import contextmanager
import random
from typing import List, Sequence, Iterator, MutableSequence
from decimal import Decimal
from scapy.all import Packet
import bisect
import numpy as np


class PacketTimeWrapper(MutableSequence[Decimal]):
    def __init__(self, packets: Sequence[Packet]):
        self.packets = packets

    def __len__(self) -> int:
        return len(self.packets)

    def __getitem__(self, index):
        return self.packets[index].time

    def __setitem__(self, index, value):
        self.packets[index].time = value

    def insert(self, *args):  # Needed for MutableSequence
        raise NotImplementedError

    def __delitem__(self, *args):  # Needed for MutableSequence
        raise NotImplementedError


def clamp(value, minvalue, maxvalue):
    return max(min(value, maxvalue), minvalue)


def random_float_range(start: float, stop: float) -> float:
    return start + random.random() * (stop - start)


def random_float_range_dec(start: Decimal, stop: Decimal) -> Decimal:
    return start + Decimal(random.random()) * (stop - start)


@contextmanager
def normalized_times(packetlist: MutableSequence[Packet]) -> Iterator[Sequence[Packet]]:
    """Contextmanager that normalizes packet timestamps and restores them afterwards."""
    basetime = normalize_times(packetlist)
    yield packetlist
    restore_times(packetlist, basetime)


def normalize_times(packetlist: MutableSequence[Packet]) -> Decimal:
    """Normalize timestamps and return first time."""
    return normalize_times_from_times(PacketTimeWrapper(packetlist))


def normalize_times_from_times(packetlist: MutableSequence[Decimal]) -> Decimal:
    """Normalize timestamps and return first time."""
    logging.info("Normalizing timestamps...")

    if len(packetlist) == 0:
        return Decimal(0)

    basetime = packetlist[0]
    if basetime:
        for i in range(len(packetlist)):
            packetlist[i] -= basetime
    return basetime


def restore_times(packetlist: Sequence[Packet], basetime: Decimal):
    """Restore previously normalized timestamps."""
    logging.info("Restoring timestamps...")
    if basetime:
        for i in packetlist:
            i.time += basetime


def get_deltas(packets: Sequence[Packet]) -> List[Decimal]:
    return get_deltas_from_times(PacketTimeWrapper(packets))


def get_deltas_from_times(times: Sequence[Decimal]) -> List[Decimal]:
    # First packet has no delta
    return [ Decimal(0) ] + [ times[i + 1] - times[i] for i in range(len(times) - 1) ]


def seek_right(packets: Sequence[Packet], time: Decimal) -> int:
    return seek(packets, time, True)


def seek(packets: Sequence[Packet], time: Decimal, bisect_right: bool = False) -> int:
    """Return index of packet with nearest timestamp to given timestamp."""

    # bisect doesn't accept a key function, so we provide a wrapper returning keys from the original list
    wrapped = PacketTimeWrapper(packets)

    if bisect_right:
        return bisect.bisect_right(wrapped, time)
    return bisect.bisect_left(wrapped, time)


def sliding_time_window(packetlist: Sequence[Packet], winsize_seconds: Decimal):
    winsize_seconds = abs(winsize_seconds)
    times = np.array([ i.time for i in packetlist ])

    for i, packet_time in enumerate(times):
        # winstart = seek(packetlist, packet.time - winsize_seconds)
        # winstop = seek_right(packetlist, packet.time + winsize_seconds)
        winstart = bisect.bisect_left(times, packet_time - winsize_seconds)
        winstop = bisect.bisect_right(times, packet_time + winsize_seconds)
        window = packetlist[winstart:winstop]
        print(i, "/", len(packetlist), " winsize: ", len(window))
        yield window
