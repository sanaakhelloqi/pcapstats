import libs.mlvideos as mlvideos

from pathlib import Path
from decimal import Decimal
from typing import List
import math
from scapy.all import rdpcap, RawPcapReader
import pandas as pd
import numpy as np
from scipy import stats


class Pcap:
    def __init__(self, file: Path):
        self.file = file
        self.stats = {"pcap": str(file)}
        self.deltas = None

    def get_times(self) -> List[Decimal]:
        return [i.time for i in rdpcap(str(self.file))]

    def get_length(self) -> List[Decimal]:
        return [len(i) for i in rdpcap(str(self.file))]

    def get_total_length(self):
        count = 0
        for i in rdpcap(str(self.file)):
            count += len(i)
        return math.floor((count*8)/1000)

    def get_packets_count(self):
        count = 0
        for (pkt_data, pkt_metadata,) in RawPcapReader(str(self.file)):
            count += 1
        return count

    def get_packets_count_by_second(self):
        count = 0
        second = 1.000000
        first_time = self.get_times()[0]
        count_list = []

        for i in self.get_times():
            j = i - first_time
            if (j > 2):
                count_list.append(count)
                for k in range(j - 2):
                    count_list.append(0)
                count = 0
            if Decimal(i - first_time) <= second:
                count += 1
            else:
                count_list.append(count)
                first_time = i
                count = 1
        count_list.append(count)
        return count_list

    def get_download_rate_by_second(self):
        set_of_src = set()
        times = []
        count_download = 0
        count_0 = 0
        count_1 = 0

        for i in rdpcap(str(self.file)):
            set_of_src.add(i.src)
            set_of_src.add(i.dst)

        Liste = list(set_of_src)

        if len(Liste) > 2:
            for j in Liste:
                for i in rdpcap(str(self.file)):
                    if j != i.src and j != i.dst:
                        Liste.remove(j)
                        break

            src_list = Liste

            for i in rdpcap(str(self.file)):
                if i.dst in src_list:
                    count_download += len(i)
        else:

            for i in rdpcap(str(self.file)):
                if i.dst == Liste[0]:
                    count_0 += 1
                elif i.dst == Liste[1]:
                    count_1 += 1

            if count_0 > count_1:
                src = Liste[0]
            else:
                src = Liste[1]

            for i in rdpcap(str(self.file)):
                if i.dst == src:
                    count_download += len(i)
        times =self.get_times()
        mlvideos.normalize_times_from_times(times)
        download_rate = math.floor(((8* count_download)/times[-1])/1000)
        return download_rate

    def get_upload_rate_by_second(self):
        set_of_src = set()
        count_upload = 0
        count_0 = 0
        count_1 = 0
        times = []
        for i in rdpcap(str(self.file)):
            set_of_src.add(i.src)
            set_of_src.add(i.dst)

        Liste = list(set_of_src)
        if len(Liste) > 2:
            for j in Liste:
                for i in rdpcap(str(self.file)):
                    if j != i.src and j != i.dst:
                        Liste.remove(j)
                        break

            src_list = Liste

            for i in rdpcap(str(self.file)):
                if i.src in src_list:
                    count_upload += len(i)
        else:

            for i in rdpcap(str(self.file)):
                if i.dst == Liste[0]:
                    count_0 += 1
                elif i.dst == Liste[1]:
                    count_1 += 1

            if count_0 > count_1:
                src = Liste[0]
            else:
                src = Liste[1]

            for i in rdpcap(str(self.file)):
                if i.src == src:
                    count_upload += len(i)

        times = self.get_times()
        mlvideos.normalize_times_from_times(times)

        upload_rate =  math.floor(((8*count_upload)/times[-1])/1000)
        return upload_rate

    def calc_deltas(self, start=Decimal(0), end=Decimal(0)):
        times = self.get_times()
        mlvideos.normalize_times_from_times(times)
        end = times[-1] if end == Decimal(0) else end
        times = [i for i in times if start <= i <= end]
        self.deltas = list([float(delta) for delta in mlvideos.get_deltas_from_times(times)])

    def get_deltas(self) -> List[float]:
        if not self.deltas:
            self.calc_deltas()
        return self.deltas

    def get_count(self):
        if not self.deltas:
            self.calc_deltas()
        else:
            self.stats["count"] = pd.Series(self.deltas).count()

    def get_mean(self):
        if not self.deltas:
            self.calc_deltas()
        else:
            self.stats["mean"] = pd.Series(self.deltas).mean()

    def get_std(self):
        if not self.deltas:
            self.calc_deltas()
        else:
            self.stats["std"] = pd.Series(self.deltas).std()

    def get_min(self):
        if not self.deltas:
            self.calc_deltas()
        else:
            self.stats["min"] = pd.Series(self.deltas).min()

    def get_max(self):
        if not self.deltas:
            self.calc_deltas()
        else:
            self.stats["max"] = pd.Series(self.deltas).max()

    def get_variance(self):
        if not self.deltas:
            self.calc_deltas()
        else:
            self.stats["variance"] = np.var(self.deltas)

    def get_variance_coefficient(self):
        if not self.deltas:
            self.calc_deltas()
        else:
            self.stats["variance_coefficient"] = np.std(self.deltas) / np.mean(self.deltas)

    def get_mode(self):
        if not self.deltas:
            self.calc_deltas()
        else:
            self.stats["mode"] = stats.mode(self.deltas)[0]

    def get_kurtosis(self):
        if not self.deltas:
            self.calc_deltas()
        else:
            self.stats["kurtosis"] = stats.mstats.kurtosis(self.deltas)

    def get_skewness(self):
        if not self.deltas:
            self.calc_deltas()
        else:
            self.stats["skewness"] = stats.skew(self.deltas)

    def get_median(self):
        if not self.deltas:
            self.calc_deltas()
        else:
            self.stats["median"] = np.median(self.deltas)

    def get_autocorrelation(self, lag=0):
        if not self.deltas:
            self.calc_deltas()
        else:
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
