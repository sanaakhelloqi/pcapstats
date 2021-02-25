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

    def get_length(self) -> List[int]:
        return [len(i) for i in rdpcap(str(self.file))]

    def get_total_length(self):
        count = 0
        for i in rdpcap(str(self.file)):
            count += len(i)
        return math.floor((count*8)/1000)

    def get_communication_percent(self, partner_ip):
        counter = 0
        for i in rdpcap(str(self.file)):
            if (i.src == partner_ip or i.dst == partner_ip) and (i.src in self.get_list_of_host() or i.dst in self.get_list_of_host()):
                counter += 1
        percent = counter / self.get_communication_number_with_host()
        return percent

    def remove_src(self, Liste):
        for j in Liste:
            for i in rdpcap(str(self.file)):
                if j != i.src and j != i.dst:
                    Liste.remove(j)
                    break

    def get_list_of_host(self):
        set_of_src = set()
        for i in rdpcap(str(self.file)):
            set_of_src.add(i.src)
            set_of_src.add(i.dst)
        Liste = list(set_of_src)
        if len(Liste) > 2:
            self.remove_src(Liste)
        else:
            Liste.clear()
            Liste.append(self.get_src(Liste))
        return Liste

    def get_src(self, Liste):
        count_0 = 0
        count_1 = 0
        for i in rdpcap(str(self.file)):
            if i.dst == Liste[0]:
                count_0 += 1
            elif i.dst == Liste[1]:
                count_1 += 1
        if count_0 > count_1:
            src = Liste[0]
        else:
            src = Liste[1]
        return src

    def get_list_of_partners(self):
        set_of_src = set()
        set_of_partner = set()
        for i in rdpcap(str(self.file)):
            set_of_src.add(i.src)
            set_of_src.add(i.dst)
        Liste = list(set_of_src)
        if len(Liste) > 2:
            self.remove_src(Liste)
            for i in rdpcap(str(self.file)):
                if i.src not in Liste:
                    set_of_partner.add(i.src)
                if i.dst not in Liste:
                    set_of_partner.add(i.dst)
        else:
            src = self.get_src(Liste)
            for i in rdpcap(str(self.file)):
                if i.src != src:
                    set_of_partner.add(i.src)
                if i.dst != src:
                    set_of_partner.add(i.dst)
        return list(set_of_partner)

    def get_communication_number_with_host(self):
        coll = []
        counter = 0
        set_of_src = set()
        for i in rdpcap(str(self.file)):
            coll.append((i.src, i.dst))
            set_of_src.add(i.src)
            set_of_src.add(i.dst)
        Liste = list(set_of_src)
        if len(Liste) > 2:
            self.remove_src(Liste)
            src_list = Liste
            for i in src_list:
                for j in coll:
                    if j[0] == i or j[1] == i:
                        counter += 1
        else:
            src = self.get_src(Liste)
            for j in coll:
                if j[0] == src or j[1] == src:
                    counter += 1
        return counter

    def get_partner_number_to_host(self):
        set_of_src = set()
        set_of_partner = set()
        for i in rdpcap(str(self.file)):
            set_of_src.add(i.src)
            set_of_src.add(i.dst)
        Liste = list(set_of_src)
        if len(Liste) > 2:
            self.remove_src(Liste)
            src_list = Liste
            for i in rdpcap(str(self.file)):
                if i.src in src_list:
                    set_of_partner.add((i.src, i.dst))
        else:
            src = self.get_src(Liste)
            for i in rdpcap(str(self.file)):
                if i.src == src:
                    set_of_partner.add((i.src, i.dst))
        return len(set_of_partner)

    def get_list_partner_communication_percent(self):
        list1 = self.get_list_of_partners()
        list2 = []
        for i in list1:
            list2.append((i, self.get_communication_percent(i)))
        return list2

    def get_frequency_of_video_stalls(self, puffer, bitrate):
        return (bitrate - self.get_download_rate_by_second()) / puffer

    def get_duration_of_video_stalls(self, puffer):
        return puffer / self.get_download_rate_by_second()

    def get_stalls_number(self, puffer, bitrate):
        times = self.get_times()
        mlvideos.normalize_times_from_times(times)
        return self.get_frequency_of_video_stalls(puffer, bitrate) * times[-1]

    def get_total_length_download_bytes(self):
        set_of_src = set()
        count_download = 0
        for i in rdpcap(str(self.file)):
            set_of_src.add(i.src)
            set_of_src.add(i.dst)
        Liste = list(set_of_src)
        if len(Liste) > 2:
            self.remove_src(Liste)
            src_list = Liste
            for i in rdpcap(str(self.file)):
                if i.dst in src_list:
                    count_download += len(i)
        else:
            src = self.get_src(Liste)
            for i in rdpcap(str(self.file)):
                if i.dst == src:
                    count_download += len(i)
        return count_download

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
                for k in range(j-2):
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
        count_download = 0
        for i in rdpcap(str(self.file)):
            set_of_src.add(i.src)
            set_of_src.add(i.dst)
        Liste = list(set_of_src)
        if len(Liste) > 2:
            self.remove_src(Liste)
            src_list = Liste
            for i in rdpcap(str(self.file)):
                if i.dst in src_list:
                    count_download += len(i)
        else:
            src = self.get_src(Liste)
            for i in rdpcap(str(self.file)):
                if i.dst == src:
                    count_download += len(i)
        times = self.get_times()
        mlvideos.normalize_times_from_times(times)
        download_rate = math.floor(((8 * count_download)/times[-1]))
        return download_rate

    def get_upload_rate_by_second(self):
        set_of_src = set()
        count_upload = 0
        for i in rdpcap(str(self.file)):
            set_of_src.add(i.src)
            set_of_src.add(i.dst)
        Liste = list(set_of_src)
        if len(Liste) > 2:
            self.remove_src(Liste)
            src_list = Liste
            for i in rdpcap(str(self.file)):
                if i.src in src_list:
                    count_upload += len(i)
        else:
            src = self.get_src(Liste)
            for i in rdpcap(str(self.file)):
                if i.src == src:
                    count_upload += len(i)
        times = self.get_times()
        mlvideos.normalize_times_from_times(times)
        upload_rate = math.floor(((8*count_upload)/times[-1])/1000)
        return upload_rate

    def get_page_load_time_half(self):
        size = math.floor(self.get_total_length_download_bytes()/2)
        return self.get_page_load_time(size)

    def get_page_load_time_quarter(self):
        size = math.floor(self.get_total_length_download_bytes()/4)
        return self.get_page_load_time(size)

    def get_page_load_time_three_quarters(self):
        size = math.floor(self.get_total_length_download_bytes()*3/4)
        return self.get_page_load_time(size)

    def get_page_load_time(self):
        set_of_src = set()
        count_download = 0
        page_load_time = []
        for i in rdpcap(str(self.file)):
            set_of_src.add(i.src)
            set_of_src.add(i.dst)
        Liste = list(set_of_src)
        if len(Liste) > 2:
            self.remove_src(Liste)
            src_list = Liste
            for i in rdpcap(str(self.file)):
                if i.dst in src_list:
                    if count_download <= self.get_total_length_download_bytes():
                        count_download += len(i)
                        page_load_time.append(i.time)
                    else:
                        break
        else:
            src = self.get_src(Liste)
            for i in rdpcap(str(self.file)):
                if i.dst == src:
                    if count_download <= self.get_total_length_download_bytes():
                        count_download += len(i)
                        page_load_time.append(i.time)
                    else:
                        break
        mlvideos.normalize_times_from_times(page_load_time)
        return page_load_time[-1]

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
