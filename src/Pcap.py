import libs.mlvideos as mlvideos

from pathlib import Path
from decimal import Decimal
from typing import List

from scapy.all import rdpcap
import pandas as pd
import numpy as np
from scipy import stats


class Pcap:
    def __init__(self, file: Path):
        self.file = file
        self.deltas = self.get_deltas()
        self.stats = {"pcap": str(file)}

    def get_times(self) -> List[Decimal]:
        return [i.time for i in rdpcap(str(self.file))]

    def get_deltas(self, start=Decimal(0), end=Decimal(0)) -> List[float]:
        times = self.get_times()
        mlvideos.normalize_times_from_times(times)
        end = times[-1] if end == Decimal(0) else end
        times = [i for i in times if start <= i <= end]
        return list([float(delta) for delta in mlvideos.get_deltas_from_times(times)])

    def get_count(self):
        self.stats["count"] = pd.Series(self.deltas).count()

    def get_mean(self):
        self.stats["mean"] = pd.Series(self.deltas).mean()

    def get_std(self):
        self.stats["std"] = pd.Series(self.deltas).std()

    def get_min(self):
        self.stats["min"] = pd.Series(self.deltas).min()

    def get_max(self):
        self.stats["max"] = pd.Series(self.deltas).max()

    def get_variance(self):
        self.stats["variance"] = np.var(self.deltas)

    def get_variance_coefficient(self):
        self.stats["variance_coefficient"] = np.std(self.deltas) / np.mean(self.deltas)

    def get_mode(self):
        self.stats["mode"] = stats.mode(self.deltas)[0]

    def get_kurtosis(self):
        self.stats["kurtosis"] = stats.mstats.kurtosis(self.deltas)

    def get_skewness(self):
        self.stats["skewness"] = stats.skew(self.deltas)

    def get_median(self):
        self.stats["median"] = np.median(self.deltas)

    def get_autocorrelation(self, lag=0):
        self.stats["autocorrelation"] = pd.Series(self.deltas).autocorr(lag)

    def collect_stats(self):
        self.get_mean()
        self.get_std()
        self.get_min()
        self.get_max()
        self.get_variance()
        self.get_variance_coefficient()
        self.get_mode()
        self.get_kurtosis()
        self.get_skewness()
        self.get_median()
        self.get_autocorrelation()

    def get_stats(self):
        self.collect_stats()
        return pd.DataFrame.from_dict(self.stats)
