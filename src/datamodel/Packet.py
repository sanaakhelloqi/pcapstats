from dataclasses import dataclass
from decimal import Decimal

from typing import List


@dataclass
class Packet:
    time: Decimal
    srcIp: str
    srcPort: int
    dstIp: str
    dstPort: int
    IPv: int
    type: str
    length: int


class Packets:
    def __init__(self, packets: List[Packet]):
        self.packets = packets

    def get_packets(self) -> List[Packet]:
        return self.packets
