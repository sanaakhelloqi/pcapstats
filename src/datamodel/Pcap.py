from src.datamodel.Packet import Packet, Packets

from pathlib import Path
from decimal import Decimal
from scapy.all import rdpcap
from scapy.layers.inet import UDP, TCP


class Pcap:
    def __init__(self, file: Path):
        self.file = file

    def read(self) -> Packets:
        packets = []
        for pkt in rdpcap(str(self.file)):
            packet = Packet(Decimal(pkt.time),
                            str(pkt.src),
                            int(pkt.sport),
                            str(pkt.dst),
                            int(pkt.dport),
                            int(pkt.version),
                            self.determine_layer_type(pkt),
                            len(pkt)
                            )
            packets.append(packet)
        return Packets(packets)

    @staticmethod
    def determine_layer_type(pkt) -> str:
        if pkt.haslayer(UDP):
            return "UDP"
        elif pkt.haslayer(TCP):
            return "TCP"
        else:
            return "other"
