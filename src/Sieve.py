from src.PacketCapture import PacketCapture
from src.Comparator import Comparator
from src.UnanimityVoter import UnanimityVoter

from pathlib import Path
import json

try:
    import importlib.resources as pkg_resources
except ImportError:
    import importlib_resources as pkg_resources


class Sieve:
    def __init__(self, original: PacketCapture, target: PacketCapture, thresholds_file: str):
        self.original = original
        self.target = target

        self.weights = self.load_thresholds_from_file(thresholds_file)

    @staticmethod
    def load_thresholds_from_file(file: str) -> dict:
        if file:
            with Path(file).open("r") as thresholds_file:
                thresholds = json.loads(thresholds_file.read())
        else:
            with pkg_resources.path("resources", "default_thresholds.json") as thresholds_file:
                thresholds = json.loads(thresholds_file.read_text())
        return thresholds

    def calculate_metrics(self):
        comp = Comparator(self.original, self.target)
        comp.calculate_metrics()

        return comp.get_comparisons(raw=True)

    def sieve(self) -> bool:
        metrics = self.calculate_metrics()
        voter = UnanimityVoter(metrics, self.weights)
        return voter.vote()
