from src.PacketCapture import PacketCapture
from src.datamodel.MinLog import MinLogReader
from src.datamodel.Pcap import Pcap

from pathlib import Path
from typing import Union


def read_file(file: str) -> Union[None, PacketCapture]:
    file = Path(file)
    file_type = file.suffix.lower()

    if file_type == ".pcap":
        packets = Pcap(file).read()
        return PacketCapture(file, packets)
    elif file_type == ".log":
        packets = MinLogReader(file).read()
        return PacketCapture(file, packets)
    else:
        return
