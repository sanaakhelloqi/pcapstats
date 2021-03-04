import libs.mlvideos as mlvideos
import math
import pandas as pd
import numpy as np
import decimal
from pathlib import Path
from decimal import Decimal
from typing import List
from scapy.all import rdpcap, RawPcapReader
from scipy import stats


class Pcap:
    def __init__(self, file: Path):
        self.file = file
        self.stats = {"pcap": str(file)}
        self.deltas = None
        self.times = self.get_times()
        self.lengths = self.get_lengths()
        self.total_length_in_mbit = self.get_total_length_in_mbit()
        self.packets_count = self.get_packets_count()
        self.list_of_tuple_src_dst = self.get_list_of_tuple_src_dst()
        self.set_of_all_ip_addr = self.get_set_of_all_ip_addr()

    def get_list_of_tuple_src_dst(self):
        return [(pkt.src, pkt.dst) for pkt in rdpcap(str(self.file))]

    # get_times returns a list of arrival time of packets
    def get_times(self) -> List[Decimal]:
        return [pkt.time for pkt in rdpcap(str(self.file))]

    # get_length returns a list of length of packets
    def get_lengths(self) -> List[int]:
        return [len(pkt) for pkt in rdpcap(str(self.file))]

    # get_total_length returns the total length of packets in mbit
    def get_total_length_in_mbit(self):
        total_length = 0
        for pkt in rdpcap(str(self.file)):
            total_length += len(pkt)
        return decimal.Decimal(total_length) * 8 / 1000000  # from byte to mbit

    # returns the packets count
    def get_packets_count(self):
        packets_count = 0
        for (pkt_data, pkt_metadata,) in RawPcapReader(str(self.file)):
            packets_count += 1
        return packets_count

    def get_frequency_of_video_stalls(self, puffer_second, bitrate_mbit):
        return max(((bitrate_mbit - self.get_download_rate_by_second()) / puffer_second), 0)

    def get_duration_of_video_stalls(self, puffer_second):
        return puffer_second / self.get_download_rate_by_second()

    def get_stalls_number(self, puffer_second, bitrate_mbit):
        mlvideos.normalize_times_from_times(self.times)
        return max(math.floor(self.get_frequency_of_video_stalls(puffer_second, bitrate_mbit) * self.times[-1]), 0)

    def calc_deltas(self, start=Decimal(0), end=Decimal(0)):
        mlvideos.normalize_times_from_times(self.times)
        end = self.times[-1] if end == Decimal(0) else end
        times_ = [i for i in self.times if start <= i <= end]
        self.deltas = list([float(delta) for delta in mlvideos.get_deltas_from_times(times_)])

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

    # returns percent of the communication between host and the partner_ip --> how much connections with the
    # partner_ip through the whole connections
    def get_communication_percent(self, partner_ip):
        communication_host_partnerip_counter = 0
        for tuple in self.list_of_tuple_src_dst:
            if (tuple[0] == partner_ip or tuple[1] == partner_ip) and (
                    tuple[0] in self.get_list_of_host_ip() or tuple[1] in self.get_list_of_host_ip()):
                communication_host_partnerip_counter += 1
        percent = communication_host_partnerip_counter / self.get_communication_number_with_host()
        return percent

    # To get a list just of host ips
    def remove_partner_ips(self, list_of_all_ip_addr):
        for ip in list_of_all_ip_addr:
            for tuple in self.list_of_tuple_src_dst:
                if ip != tuple[0] and ip != tuple[1]:
                    list_of_all_ip_addr.remove(ip)
                    break

    # To get the host if we have just 2 ips (1 host, 1 partner)
    def get_host_ip(self, list_of_all_ip_addr):
        count_0 = 0
        count_1 = 0
        for tuple in self.list_of_tuple_src_dst:
            if tuple[1] == list_of_all_ip_addr[0]:
                count_0 += 1
            elif tuple[1] == list_of_all_ip_addr[1]:
                count_1 += 1
        if count_0 > count_1:
            host_ip = list_of_all_ip_addr[0]
        else:
            host_ip = list_of_all_ip_addr[1]
        return host_ip

    # removes partner ip addresses from the list of all ip addr --> returns the list of host ip
    def get_list_of_host_ip(self):
        list_of_all_ip_addr = list(self.set_of_all_ip_addr)
        if len(list_of_all_ip_addr) > 2:
            self.remove_partner_ips(list_of_all_ip_addr)
        else:
            list_of_all_ip_addr.clear()
            list_of_all_ip_addr.append(self.get_host_ip(list_of_all_ip_addr))
        return list_of_all_ip_addr

    # returns a list of all ip addrs
    def get_set_of_all_ip_addr(self):
        set_of_all_ip_addr = set()
        for tuple in self.list_of_tuple_src_dst:
            set_of_all_ip_addr.add(tuple[0])
            set_of_all_ip_addr.add(tuple[1])
        return set_of_all_ip_addr

    # returns a list of ip partners
    def get_list_of_partners(self):
        set_of_partner = set()
        list_of_all_ip_addr = list(self.set_of_all_ip_addr)
        if len(list_of_all_ip_addr) > 2:
            self.remove_partner_ips(list_of_all_ip_addr)
            for tuple in self.list_of_tuple_src_dst:
                if tuple[0] not in list_of_all_ip_addr:
                    set_of_partner.add(tuple[0])
                if tuple[1] not in list_of_all_ip_addr:
                    set_of_partner.add(tuple[1])
        else:
            host_ip = self.get_host_ip(list_of_all_ip_addr)
            for tuple in self.list_of_tuple_src_dst:
                if tuple[0] != host_ip:
                    set_of_partner.add(tuple[0])
                if tuple[1] != host_ip:
                    set_of_partner.add(tuple[1])
        return list(set_of_partner)

    # returns how much connections with the host
    def get_communication_number_with_host(self):
        counter = 0
        list_of_all_ip_addr = list(self.set_of_all_ip_addr)
        if len(list_of_all_ip_addr) > 2:
            self.remove_partner_ips(list_of_all_ip_addr)
            host_list = list_of_all_ip_addr
            for host in host_list:
                for tuple in self.list_of_tuple_src_dst:
                    if tuple[0] == host or tuple[1] == host:
                        counter += 1
        else:
            host_ip = self.get_host_ip(list_of_all_ip_addr)
            for tuple in self.list_of_tuple_src_dst:
                if tuple[0] == host_ip or tuple[1] == host_ip:
                    counter += 1
        return counter

    # returns how much partner with the host
    def get_partner_number_to_host(self):
        set_of_partner = set()
        list_of_all_ip_addr = list(self.set_of_all_ip_addr)
        if len(list_of_all_ip_addr) > 2:
            self.remove_partner_ips(list_of_all_ip_addr)
            src_list = list_of_all_ip_addr
            for i in rdpcap(str(self.file)):
                if i.src in src_list:
                    set_of_partner.add((i.src, i.dst))
        else:
            host_ip = self.get_host_ip(list_of_all_ip_addr)
            for tuple in self.list_of_tuple_src_dst:
                if tuple[0] == host_ip:
                    set_of_partner.add((tuple[0], tuple[1]))
        return len(set_of_partner)

    # returns a list of tuples --> ip of the partner, how much percent communication with the host
    def get_list_partner_communication_percent(self):
        list_of_partners = self.get_list_of_partners()
        list_of_tuple_ip_communication_percent = []
        for i in list_of_partners:
            list_of_tuple_ip_communication_percent.append((i, self.get_communication_percent(i)))
        return list_of_tuple_ip_communication_percent

    def get_total_length_download(self):
        download_length = 0
        list_of_all_ip_addr = list(self.set_of_all_ip_addr)
        if len(list_of_all_ip_addr) > 2:
            self.remove_partner_ips(list_of_all_ip_addr)
            src_list = list_of_all_ip_addr
            for i in rdpcap(str(self.file)):
                if i.dst in src_list:
                    download_length += len(i)
        else:
            host_ip = self.get_host_ip(list_of_all_ip_addr)
            for i in rdpcap(str(self.file)):
                if i.dst == host_ip:
                    download_length += len(i)
        return decimal.Decimal(download_length) * 8 / 1000000  # in mbit

    def get_packets_count_by_second(self):
        count = 0
        second = 1
        first_time = self.times[0]
        count_list = []
        for i in self.times:
            j = math.ceil(i - first_time)
            if j > 2:
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
        download_length = 0
        list_of_all_ip_addr = list(self.set_of_all_ip_addr)
        if len(list_of_all_ip_addr) > 2:
            self.remove_partner_ips(list_of_all_ip_addr)
            src_list = list_of_all_ip_addr
            for i in rdpcap(str(self.file)):
                if i.dst in src_list:
                    download_length += len(i)
        else:
            host_ip = self.get_host_ip(list_of_all_ip_addr)
            for i in rdpcap(str(self.file)):
                if i.dst == host_ip:
                    download_length += len(i)
        download_length_mbit = decimal.Decimal(download_length) * 8 / 1000000  # from byte to mbit
        mlvideos.normalize_times_from_times(self.times)
        return decimal.Decimal((download_length_mbit / self.times[-1]))

    def get_upload_rate_by_second(self):
        upload_length = 0
        list_of_all_ip_addr = list(self.set_of_all_ip_addr)
        if len(list_of_all_ip_addr) > 2:
            self.remove_partner_ips(list_of_all_ip_addr)
            src_list = list_of_all_ip_addr
            for i in rdpcap(str(self.file)):
                if i.src in src_list:
                    upload_length += len(i)
        else:
            host_ip = self.get_host_ip(list_of_all_ip_addr)
            for i in rdpcap(str(self.file)):
                if i.src == host_ip:
                    upload_length += len(i)
        upload_length_mbit = decimal.Decimal(upload_length) * 8 / 1000000  # from byte to mbit
        mlvideos.normalize_times_from_times(self.times)
        return decimal.Decimal((upload_length_mbit / self.times[-1]))

    def get_page_load_time_total(self):
        return self.get_page_load_time(self.get_total_length_download())

    def get_page_load_time_half(self):
        return self.get_page_load_time(decimal.Decimal(self.get_total_length_download() / 2))

    def get_page_load_time_three_quarters(self):
        return self.get_page_load_time(decimal.Decimal(self.get_total_length_download() * 3 / 4))

    def get_page_load_time_quarter(self):
        return self.get_page_load_time(decimal.Decimal(self.get_total_length_download() / 4))

    def get_page_load_time(self, pagesize):
        download_length = 0
        page_load_time = []
        list_of_all_ip_addr = list(self.set_of_all_ip_addr)
        if len(list_of_all_ip_addr) > 2:
            self.remove_partner_ips(list_of_all_ip_addr)
            src_list = list_of_all_ip_addr
            for i in rdpcap(str(self.file)):
                if i.dst in src_list:
                    if download_length <= pagesize:
                        download_length += len(i)
                        page_load_time.append(i.time)
                    else:
                        break
        else:
            host_ip = self.get_host_ip(list_of_all_ip_addr)
            for i in rdpcap(str(self.file)):
                if i.dst == host_ip:
                    if download_length <= pagesize:
                        download_length += len(i)
                        page_load_time.append(i.time)
                    else:
                        break
        mlvideos.normalize_times_from_times(page_load_time)
        return page_load_time[-1]
