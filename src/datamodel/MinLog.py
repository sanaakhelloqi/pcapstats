from src.datamodel.Packet import Packet, Packets

from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Dict, List, Union


class MinLogReader:
    def __init__(self, min_log: Union[str, Path]):
        self.file = Path(min_log)

    def read(self) -> Packets:
        def extract_int(key: str, _dict: dict, default: int = 0) -> int:
            try:
                return int(_dict.get(key, default))
            except ValueError:
                return 0

        with self.file.open("r") as f:
            content = [line.rstrip() for line in f.readlines()]

        headers = content[0].split(";")
        content = [c.split(";") for c in content[1:]]

        packets = []
        for pkt in self.extract_packets(content, headers):
            try:
                _time = Decimal(pkt.get("Time", 0))
            except InvalidOperation:
                _time = Decimal(0)
            _srcIp = pkt.get("SrcIP", "")
            _srcPort = extract_int("SrcPort", pkt)
            _dstIp = pkt.get("DstIP", "")
            _dstPort = extract_int("DstPort", pkt)
            _ipv = extract_int("IPv", pkt, 4)
            _type = pkt.get("Type", "")
            _size = extract_int("Size", pkt)

            packet = Packet(
                _time,
                _srcIp,
                _srcPort,
                _dstIp,
                _dstPort,
                _ipv,
                _type,
                _size
            )
            packets.append(packet)

        return Packets(packets)

    @staticmethod
    def extract_packets(content: List[List[str]], headers: list) -> List[Dict[str, str]]:
        packets = []

        for c in content:
            content_dict = {}
            for idx, value in enumerate(c):
                content_dict[headers[idx]] = value
            packets.append(content_dict)

        return packets
