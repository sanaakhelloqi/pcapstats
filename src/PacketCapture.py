import libs.mlvideos as mlvideos
from src.datamodel.Packet import Packets

from typing import List, Union
from decimal import Decimal
from pathlib import Path
import math
import collections

import pandas as pd
import numpy as np
from scipy import stats
import networkx as nx


class PacketCapture:
    def __init__(self, file: Path, packets: Packets):
        self.file = file
        self.packets = packets.get_packets()

        self.stats = {"Deltas": {},
                      "Lengths": {},
                      "Arrival times": {}}

        self.graph_representation = None
        self.deltas = None
        self.times = self.get_times()
        self.lengths = self.get_lengths()
        self.total_length = self.get_total_length()
        self.packets_count = self.get_packets_count()
        self.list_of_tuple_src_dst = self.get_list_of_tuple_src_dst()
        self.set_of_all_ip_addr = self.get_set_of_all_ip_addr()

    def get_list_of_tuple_src_dst(self):
        return [(pkt.srcIp, pkt.dstIp) for pkt in self.packets]

    def get_times(self) -> List[Decimal]:
        """returns a list of arrival time of packets

        """
        return [pkt.time for pkt in self.packets]

    def get_lengths(self) -> List[int]:
        """returns a list of length of packets

        """
        return [pkt.length for pkt in self.packets]

    def get_total_length(self):
        """returns the total length of packets in mbit
        """
        total_length = 0
        for pkt in self.packets:
            total_length += pkt.length
        return self.byte_to_kbit(Decimal(total_length))

    def get_packets_count(self):
        """returns the packets count

        """
        return len(self.get_times())

    def calc_deltas(self, start=Decimal(0), end=Decimal(0)):
        mlvideos.normalize_times_from_times(self.times)
        end = self.times[-1] if end == Decimal(0) else end
        times_ = [i for i in self.times if start <= i <= end]
        self.deltas = list([float(delta) for delta in mlvideos.get_deltas_from_times(times_)])

    def get_deltas(self) -> List[float]:
        if not self.deltas:
            self.calc_deltas()
        return self.deltas

    def get_deltas_count(self):
        if not self.deltas:
            self.calc_deltas()
        else:
            self.stats["Deltas"]["count"] = float(pd.Series(self.deltas).count())

    def get_deltas_mean(self):
        if not self.deltas:
            self.calc_deltas()
        else:
            self.stats["Deltas"]["mean"] = float(pd.Series(self.deltas).mean())

    def get_deltas_std(self):
        if not self.deltas:
            self.calc_deltas()
        else:
            self.stats["Deltas"]["std"] = float(pd.Series(self.deltas).std())

    def get_deltas_min(self):
        if not self.deltas:
            self.calc_deltas()
        else:
            self.stats["Deltas"]["min"] = float(pd.Series(self.deltas).min())

    def get_deltas_max(self):
        if not self.deltas:
            self.calc_deltas()
        else:
            self.stats["Deltas"]["max"] = float(pd.Series(self.deltas).max())

    def get_deltas_variance(self):
        if not self.deltas:
            self.calc_deltas()
        else:
            self.stats["Deltas"]["variance"] = float(np.var(self.deltas))

    def get_deltas_variance_coefficient(self):
        if not self.deltas:
            self.calc_deltas()
        else:
            self.stats["Deltas"]["variance_coefficient"] = float(np.std(self.deltas) / np.mean(self.deltas))

    def get_deltas_mode(self):
        if not self.deltas:
            self.calc_deltas()
        else:
            self.stats["Deltas"]["mode"] = float(stats.mode(self.deltas)[0])

    def get_deltas_kurtosis(self):
        if not self.deltas:
            self.calc_deltas()
        else:
            self.stats["Deltas"]["kurtosis"] = float(stats.mstats.kurtosis(self.deltas))

    def get_deltas_skewness(self):
        if not self.deltas:
            self.calc_deltas()
        else:
            self.stats["Deltas"]["skewness"] = float(stats.skew(self.deltas))

    def get_deltas_median(self):
        if not self.deltas:
            self.calc_deltas()
        else:
            self.stats["Deltas"]["median"] = float(np.median(self.deltas))

    def get_lengths_count(self):
        self.stats["Lengths"]["count"] = float(pd.Series(self.lengths).count())

    def get_lengths_mean(self):
        self.stats["Lengths"]["mean"] = float(pd.Series(self.lengths).mean())

    def get_lengths_std(self):
        self.stats["Lengths"]["std"] = float(pd.Series(self.lengths).std())

    def get_lengths_min(self):
        self.stats["Lengths"]["min"] = float(pd.Series(self.lengths).min())

    def get_lengths_max(self):
        self.stats["Lengths"]["max"] = float(pd.Series(self.lengths).max())

    def get_lengths_variance(self):
        self.stats["Lengths"]["variance"] = float(np.var(self.lengths))

    def get_lengths_variance_coefficient(self):
        self.stats["Lengths"]["variance_coefficient"] = float(np.std(self.lengths) / np.mean(self.lengths))

    def get_lengths_mode(self):
        self.stats["Lengths"]["mode"] = float(stats.mode(self.lengths)[0])

    def get_lengths_kurtosis(self):
        self.stats["Lengths"]["kurtosis"] = float(stats.mstats.kurtosis(self.lengths))

    def get_lengths_skewness(self):
        self.stats["Lengths"]["skewness"] = float(stats.skew(self.lengths))

    def get_lengths_median(self):
        self.stats["Lengths"]["median"] = float(np.median(self.lengths))

    def get_times_min(self):
        mlvideos.normalize_times_from_times(self.times)
        self.stats["Arrival times"]["min"] = float(pd.Series(self.times).min())

    def get_times_max(self):
        mlvideos.normalize_times_from_times(self.times)
        self.stats["Arrival times"]["max"] = float(pd.Series(self.times).max())

    def get_times_median(self):
        mlvideos.normalize_times_from_times(self.times)
        self.stats["Arrival times"]["median"] = float(np.median(self.times))

    def collect_stats(self):
        # deltas
        self.get_deltas_count()
        self.get_deltas_mean()
        self.get_deltas_std()
        self.get_deltas_min()
        self.get_deltas_max()
        self.get_deltas_variance()
        self.get_deltas_variance_coefficient()
        self.get_deltas_mode()
        self.get_deltas_kurtosis()
        self.get_deltas_skewness()
        self.get_deltas_median()
        # lengths
        self.get_lengths_count()
        self.get_lengths_mean()
        self.get_lengths_std()
        self.get_lengths_min()
        self.get_lengths_max()
        self.get_lengths_variance()
        self.get_lengths_variance_coefficient()
        self.get_lengths_mode()
        self.get_lengths_kurtosis()
        self.get_lengths_skewness()
        self.get_lengths_median()

        # arrival times
        self.get_times_min()
        self.get_times_max()
        self.get_times_median()

    def get_stats(self):
        self.collect_stats()
        return self.stats

    def remove_partner_ips(self, list_of_all_ip_addr):
        """To get a list just of host ips

        """
        for ip in list_of_all_ip_addr:
            for _tuple in self.list_of_tuple_src_dst:
                if ip != _tuple[0] and ip != _tuple[1]:
                    list_of_all_ip_addr.remove(ip)
                    break

    def get_host_ip(self, list_of_all_ip_addr):
        count_0 = 0
        count_1 = 0
        for _tuple in self.list_of_tuple_src_dst:
            if _tuple[1] == list_of_all_ip_addr[0]:
                count_0 += 1
            elif _tuple[1] == list_of_all_ip_addr[1]:
                count_1 += 1
        if count_0 > count_1:
            host_ip = list_of_all_ip_addr[0]
        else:
            host_ip = list_of_all_ip_addr[1]
        return host_ip

    def get_list_of_host_ip(self):
        """removes partner ip addresses from the list of all ip addr --> returns the list of host ip

        """
        list_of_all_ip_addr = list(self.set_of_all_ip_addr).copy()
        if len(list_of_all_ip_addr) > 2:
            self.remove_partner_ips(list_of_all_ip_addr)
        else:
            list_of_all_ip_addr.clear()
            list_of_all_ip_addr.append(self.get_host_ip(list(self.set_of_all_ip_addr)))
        return list_of_all_ip_addr

    def get_set_of_all_ip_addr(self):
        """returns a list of all ip addrs

        """
        set_of_all_ip_addr = set()
        for _tuple in self.list_of_tuple_src_dst:
            set_of_all_ip_addr.add(_tuple[0])
            set_of_all_ip_addr.add(_tuple[1])
        return set_of_all_ip_addr

    def get_list_of_partners(self):
        """returns a list of ip partners

        """
        set_of_partner = set()
        list_of_all_ip_addr = list(self.set_of_all_ip_addr).copy()
        if len(list_of_all_ip_addr) > 2:
            self.remove_partner_ips(list_of_all_ip_addr)
            for _tuple in self.list_of_tuple_src_dst:
                if _tuple[0] not in list_of_all_ip_addr:
                    set_of_partner.add(_tuple[0])
                if _tuple[1] not in list_of_all_ip_addr:
                    set_of_partner.add(_tuple[1])
        else:
            host_ip = self.get_host_ip(list_of_all_ip_addr)
            for _tuple in self.list_of_tuple_src_dst:
                if _tuple[0] != host_ip:
                    set_of_partner.add(_tuple[0])
                if _tuple[1] != host_ip:
                    set_of_partner.add(_tuple[1])
        return list(set_of_partner)

    def get_partner_number(self):
        return len(self.get_list_of_partners())

    def get_communication_number_with_host(self):
        """returns how much connections with the host

        """
        counter = 0
        list_of_all_ip_addr = list(self.set_of_all_ip_addr).copy()
        if len(list_of_all_ip_addr) > 2:
            self.remove_partner_ips(list_of_all_ip_addr)
            host_list = list_of_all_ip_addr
            for host in host_list:
                for _tuple in self.list_of_tuple_src_dst:
                    if _tuple[0] == host or _tuple[1] == host:
                        counter += 1
        else:
            host_ip = self.get_host_ip(list_of_all_ip_addr)
            for _tuple in self.list_of_tuple_src_dst:
                if _tuple[0] == host_ip or _tuple[1] == host_ip:
                    counter += 1
        return counter

    def get_communication_weight(self, partner_ip, percentage=False):
        """returns percent of the communication between host and the partner_ip --> how much connections with the
            partner_ip through the whole connections
        """
        communication_host_partnerip_counter = 0

        for _tuple in self.list_of_tuple_src_dst:
            if (_tuple[0] == partner_ip or _tuple[1] == partner_ip) and (
                    _tuple[0] in self.get_list_of_host_ip() or _tuple[1] in self.get_list_of_host_ip()):
                communication_host_partnerip_counter += 1

        if percentage:
            return communication_host_partnerip_counter / self.get_communication_number_with_host()
        return communication_host_partnerip_counter

    def get_list_partner_communication_percent(self):
        """returns a list of tuples --> ip of the partner, how much percent communication with the host

        """
        list_of_partners = self.get_list_of_partners()
        list_of_tuple_ip_communication_percent = []
        for partner in list_of_partners:
            list_of_tuple_ip_communication_percent.append((partner, self.get_communication_weight(partner)))
        return list_of_tuple_ip_communication_percent

    def get_ip_graph(self, directed=True):
        if not self.graph_representation:
            self.graph_representation = self.build_ip_graph(directed)
        return self.graph_representation

    def build_ip_graph(self, directed=True):
        communication = [(pkt.srcIp, pkt.dstIp) for pkt in self.packets]
        counter = collections.Counter(list(communication))
        g = nx.DiGraph()
        for edge in counter.most_common():
            g.add_edge(edge[0][0], edge[0][1], weight=edge[1])
        return g

    def get_packets_count_by_second(self):
        """returns dictionary: Keys = seconds and values= packets count

        """
        mlvideos.normalize_times_from_times(self.times)
        times_ = []
        for time in self.times:
            times_.append(math.floor(time))
        dict_ = dict(collections.Counter(times_))
        t_dict = {second: 0 for second in range(0, times_[-1] + 1)}
        for key, value in dict_.items():
            t_dict[key] += value
        return t_dict

    def get_download_rate_by_second(self):
        download_length = 0
        list_of_all_ip_addr = list(self.set_of_all_ip_addr).copy()
        if len(list_of_all_ip_addr) > 2:
            self.remove_partner_ips(list_of_all_ip_addr)
            src_list = list_of_all_ip_addr
            for pkt in self.packets:
                if pkt.dstIp in src_list:
                    download_length += pkt.length
        else:
            host_ip = self.get_host_ip(list_of_all_ip_addr)
            for pkt in self.packets:
                if pkt.dstIp == host_ip:
                    download_length += pkt.length
        download_length_kbit = self.byte_to_kbit(Decimal(download_length))
        mlvideos.normalize_times_from_times(self.times)
        return Decimal((download_length_kbit / self.times[-1]))

    def get_total_length_downloaded(self):
        download_length = 0
        list_of_all_ip_addr = list(self.set_of_all_ip_addr).copy()
        if len(list_of_all_ip_addr) > 2:
            self.remove_partner_ips(list_of_all_ip_addr)
            src_list = list_of_all_ip_addr
            for pkt in self.packets:
                if pkt.dstIp in src_list:
                    download_length += pkt.length
        else:
            host_ip = self.get_host_ip(list_of_all_ip_addr)
            for pkt in self.packets:
                if pkt.dstIp == host_ip:
                    download_length += pkt.length
        return self.byte_to_kbit(Decimal(download_length))

    def get_time_dr_dict(self):
        list_times = []
        list_lengths = []

        list_of_all_ip_addr = list(self.set_of_all_ip_addr).copy()
        if len(list_of_all_ip_addr) > 2:
            self.remove_partner_ips(list_of_all_ip_addr)
            src_list = list_of_all_ip_addr
            for pkt in self.packets:
                if pkt.dstIp in src_list:
                    list_times.append(pkt.time)
                    list_lengths.append(self.byte_to_kbit(pkt.length))
        else:
            host_ip = self.get_host_ip(list_of_all_ip_addr)
            for pkt in self.packets:
                if pkt.dstIp == host_ip:
                    list_times.append(pkt.time)
                    list_lengths.append(self.byte_to_kbit(pkt.length))

        mlvideos.normalize_times_from_times(list_times)
        list_times2 = [(math.ceil(list_times[i])) for i in range(0, len(list_times))]
        merged_list = [(list_times2[i], list_lengths[i]) for i in range(0, len(list_lengths))]
        time_dict = {}
        for packet in merged_list:
            if time_dict.get(packet[0]) is None:
                time_dict[packet[0]] = packet[1]
            else:
                time_dict[packet[0]] += packet[1]

        mlvideos.normalize_times_from_times(self.times)
        max_second = math.ceil(self.times[-1])
        time_dr_dict = {second: 0 for second in range(0, max_second + 1)}
        for key, value in time_dict.items():
            time_dr_dict[key] += value
        return time_dr_dict

    def get_delta_list(self, alpha, bitrate):
        buffer = 0
        dl = True
        play = False
        delta_t_list = []
        delta_t2_list = []
        count = 0
        time_dr_dict = self.get_time_dr_dict()
        for time, download_rate in time_dr_dict.items():
            count += 1
            buffer += download_rate / bitrate
            if dl and not play and buffer >= alpha:
                buffer = max(buffer - 1, 0)
                play = True
                dl = True
                delta_t_list.append(count + (alpha * bitrate / download_rate))
            # elif play == False and dl == True:
            elif buffer == 0 and dl and play:
                play = False
                dl = True
                delta_t2_list.append(count + ((alpha * bitrate) / (bitrate - download_rate)))

            elif play and dl:
                buffer = max(buffer - 1, 0)
        return delta_t_list

    def get_total_stall_time(self, alpha, bitrate):
        delta_t_list = self.get_delta_list(alpha, bitrate)
        total_stall_time = 0
        for time in delta_t_list[1:]:
            total_stall_time += time
        return total_stall_time

    def get_total_stall_count(self, alpha, bitrate):
        delta_t_list = self.get_delta_list(alpha, bitrate)
        if delta_t_list:
            count = len(delta_t_list) - 1
        else:
            count = 0
        return count

    def get_initial_delay(self, alpha, bitrate):
        delta_t_list = self.get_delta_list(alpha, bitrate)
        if delta_t_list:
            initial_delay = delta_t_list[0]
        else:
            initial_delay = 0
        return initial_delay

    def get_upload_rate_by_second(self):
        upload_length = 0
        list_of_all_ip_addr = list(self.set_of_all_ip_addr).copy()
        if len(list_of_all_ip_addr) > 2:
            self.remove_partner_ips(list_of_all_ip_addr)
            src_list = list_of_all_ip_addr
            for pkt in self.packets:
                if pkt.srcIp in src_list:
                    upload_length += pkt.length
        else:
            host_ip = self.get_host_ip(list_of_all_ip_addr)
            for pkt in self.packets:
                if pkt.srcIp == host_ip:
                    upload_length += pkt.length
        upload_length_kbit = self.byte_to_kbit(Decimal(upload_length))
        mlvideos.normalize_times_from_times(self.times)
        return Decimal((upload_length_kbit / self.times[-1]))

    def get_page_load_time_total(self):
        return self.get_page_load_time(self.get_total_length_downloaded())

    def get_page_load_time_half(self):
        return self.get_page_load_time(Decimal(self.get_total_length_downloaded() / 2))

    def get_page_load_time_three_quarters(self):
        return self.get_page_load_time(Decimal(self.get_total_length_downloaded() * 3 / 4))

    def get_page_load_time_quarter(self):
        return self.get_page_load_time(Decimal(self.get_total_length_downloaded() / 4))

    def get_page_load_time(self, pagesize):
        download_length = 0
        page_load_time = []
        list_of_all_ip_addr = list(self.set_of_all_ip_addr).copy()
        if len(list_of_all_ip_addr) > 2:
            self.remove_partner_ips(list_of_all_ip_addr)
            src_list = list_of_all_ip_addr
            for pkt in self.packets:
                if pkt.dstIp in src_list:
                    if download_length <= pagesize:
                        download_length += pkt.length
                        page_load_time.append(pkt.time)
                    else:
                        break
        else:
            host_ip = self.get_host_ip(list_of_all_ip_addr)
            for pkt in self.packets:
                if pkt.dstIp == host_ip:
                    if download_length <= pagesize:
                        download_length += pkt.length
                        page_load_time.append(pkt.time)
                    else:
                        break
        mlvideos.normalize_times_from_times(page_load_time)
        return page_load_time[-1]

    @staticmethod
    def byte_to_kbit(_byte: Union[int, Decimal]) -> Decimal:
        return _byte * 8 / 1000
