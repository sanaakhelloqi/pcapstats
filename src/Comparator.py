from src.Pcap import Pcap
from dtaidistance import dtw
from scipy import stats
import pandas as pd
from pathlib import Path
import math
from networkx.readwrite import json_graph
import networkx as nx
import numpy as np
np.seterr(divide='ignore', invalid='ignore')


class Comparator:
    def __init__(self, original: Pcap, target: Pcap, visualize: bool):
        self.original = original
        self.target = target
        self.viz_data = {
                "Frequencies": {},
                "CDF": {}
        }
        self.viz_graphs = {
            "original_graph": json_graph.node_link_data(self.original.get_ips_graph()),
            "target_graph":  json_graph.node_link_data(self.target.get_ips_graph())
        }
        self.comparisons = {
            "Original": {"Number of packets": self.original.get_packets_count(),
                         "Download rate in kbit/s": float(self.original.get_download_rate_by_second()),
                         "Upload rate in kbit/s": float(self.original.get_upload_rate_by_second()),
                         "Length of all packets in kbit": float(self.original.get_total_length()),
                         "Total download length in kbit": float(self.original.get_total_length_downloaded()),
                         "Total Stall time": float(self.original.get_total_stall_time(5, 8000)),
                         "Total Stall number": float(self.original.get_total_stall_count(5, 8000)),
                         "Initial delay": float(self.original.get_initial_delay(5, 8000)),
                         "Page load time in second for the total download size":
                             float(self.original.get_page_load_time_total()),
                         "Page load time for the half of the download size":
                             float(self.original.get_page_load_time_half()),
                         "Page load time for the quarter of the download size": float(
                             self.original.get_page_load_time_quarter()),
                         "Page load time for the three quarters of the download size": float(
                             self.original.get_page_load_time_three_quarters())
                         },
            "Target": {"Number of packets": self.target.get_packets_count(),
                       "Download rate in kbit/s": float(self.target.get_download_rate_by_second()),
                       "Upload rate in kbit/s": float(self.target.get_upload_rate_by_second()),
                       "Length of all packets in kbit": float(self.target.get_total_length()),
                       "Total download length in kbit": float(self.target.get_total_length_downloaded()),
                       "Total Stall time": float(self.target.get_total_stall_time(5, 8000)),
                       "Total Stall number": float(self.target.get_total_stall_count(5, 8000)),
                       "Initial delay": float(self.target.get_initial_delay(5, 8000)),
                       "Page load time in second for the total download size": float(
                           self.target.get_page_load_time_total()),
                       "Page load time for the half of the download size": float(
                           self.target.get_page_load_time_half()),
                       "Page load time for the quarter of download size": float(
                           self.target.get_page_load_time_quarter()),
                       "Page load time for the three quarters of the download size": float(
                           self.target.get_page_load_time_three_quarters())
                       },
            "Chi_squared_test": {},
            "Kolmogorov_smirnov_test": {},
            "Earth_mover_distance": {},
            "Dynamic_time_warping": {},
            #"Graph_distance": {},
        }
    #def get_graph_distance(self):
     #   self.comparisons["Graph_distance"]['graphs'] = nx.graph_edit_distance(self.original.get_ips_graph(),
      #                                                                        self.target.get_ips_graph())

    def get_data_same_length(self, data_list_ori, data_list_aug):
        n = len(data_list_ori)
        if n < 35:
            out, bins = pd.qcut(data_list_ori, n,
                                labels=False, retbins=True, duplicates='drop')
        else:
            out, bins = pd.qcut(data_list_ori, math.floor(1.88 * n ** (2 / 5)),
                                    labels=False, retbins=True, duplicates='drop')
        histogram_original, bin_edges = np.histogram(data_list_ori, bins, range=None, normed=None,
                                                     weights=None, density=None)
        histogram_augmented, bin_edges = np.histogram(data_list_aug, bins, range=None, normed=None,
                                                      weights=None, density=None)
        length_org = np.cumsum(histogram_original)[-1]
        length_aug = np.cumsum(histogram_augmented)[-1]
        if length_aug != 0:
            factor = length_org / length_aug
            histogram_augmented = [value * factor for value in histogram_augmented]
        histogram_original = [value * 1.0 for value in histogram_original]
        length_aug = np.cumsum(histogram_augmented)[-1]
        return bins, histogram_original, histogram_augmented, length_org, length_aug

    def get_data_chi_squared(self, data_list_ori, data_list_aug):
        bins, histogram_original, histogram_augmented, length_org, length_aug =\
            self.get_data_same_length(data_list_ori, data_list_aug)
        return bins, histogram_original, histogram_augmented

    def get_data_ks_test(self, data_list_ori, data_list_aug):
        bins, histogram_original, histogram_augmented, length_org, length_aug =\
            self.get_data_same_length(data_list_ori, data_list_aug)
        return bins, np.cumsum(histogram_original), np.cumsum(histogram_augmented), length_org, length_aug

    def get_chi_squared_test(self):
        bins, histogram_original, histogram_augmented = self.get_data_chi_squared(self.original.get_deltas(),
                                                                                  self.target.get_deltas())
        self.comparisons["Chi_squared_test"]['Delta'] = stats.chisquare(histogram_original, histogram_augmented).pvalue

        self.viz_data["Frequencies"]["deltas"] = \
            {
                "x": list(bins[:-1]),
                "y1": [float(x) for x in list(histogram_original)],
                "y2": [float(x) for x in list(histogram_augmented)],
                "xaxis": "Deltas in second",
                "yaxis": "Packet number"
            }
        bins_length, hist_original_length, hist_augmented_length = \
            self.get_data_chi_squared(self.original.get_lengths(), self.target.get_lengths())

        self.comparisons["Chi_squared_test"]['Length'] = \
            stats.chisquare(hist_augmented_length, hist_original_length).pvalue

        self.viz_data["Frequencies"]["lengths"] = \
            {
                "x": list(bins_length[:-1]),
                "y1": [float(x) for x in list(hist_original_length)],
                "y2": [float(x) for x in list(hist_augmented_length)],
                "xaxis": "Lengths in bytes",
                "yaxis": "Packet number"
            }

        bins_packets_seconds, hist_packets_second, hist_augmented_packets_seconds = \
            self.get_data_chi_squared(list(self.original.get_packets_count_by_second().values()),
                                      list(self.target.get_packets_count_by_second().values()))

        self.comparisons["Chi_squared_test"]['Packet number by second'] = \
            stats.chisquare(hist_augmented_packets_seconds, hist_packets_second).pvalue

        self.viz_data["Frequencies"]["packets_number"] = \
            {
                "x": list(self.original.get_packets_count_by_second().keys()),
                "y1": [float(x) for x in list(self.original.get_packets_count_by_second().values())],
                "y2": [float(x) for x in list(self.target.get_packets_count_by_second().values())],
                "xaxis": "Time in seconds",
                "yaxis": "Packet number"
            }

    def get_kolmogorov_smirnov_test(self):
        self.comparisons["Kolmogorov_smirnov_test"]['Deltas'] = stats.ks_2samp(self.target.get_deltas(),
                                                                               self.original.get_deltas()).pvalue
        self.comparisons["Kolmogorov_smirnov_test"]['Length'] = stats.ks_2samp(self.target.get_lengths(),
                                                                               self.original.get_lengths()).pvalue
        self.comparisons["Kolmogorov_smirnov_test"]['Packet number by second'] = \
            stats.ks_2samp(list(self.target.get_packets_count_by_second().values()),
                           list(self.original.get_packets_count_by_second().values())).pvalue

        bins, cumulative_original, cumulative_augmented, histmax, hist2max = self.get_data_ks_test(self.original.get_deltas(),
                                                                                self.target.get_deltas())

        self.viz_data["CDF"]["deltas"] = \
            {
                "x": list(bins[:-1]),
                "y1": [float(x/histmax if int(histmax) != 0 else x) for x in list(cumulative_original)],
                "y2": [float(x/hist2max if int(hist2max) != 0 else x) for x in list(cumulative_augmented)],
                "xaxis": "Deltas in second",
                "yaxis": "Number of packets"
            }

        bins_lengths, hist_lengths, hist2_lengths, histmax, hist2max = self.get_data_ks_test(self.original.get_lengths(),
                                                                          self.target.get_lengths())
        self.viz_data["CDF"]["lengths"] = \
            {
                "x": list(bins_lengths[:-1]),
                "y1": [float(x/histmax if int(histmax) != 0 else x) for x in list(hist_lengths)],
                "y2": [float(x/hist2max if int(hist2max) != 0 else x) for x in list(hist2_lengths)],
                "xaxis": "Lengths in bytes",
                "yaxis": "Number of packets"
            }

        bins_packet_number, hist_packet_number, hist2_packet_number, histmax, hist2max = \
            self.get_data_ks_test(list(self.original.get_packets_count_by_second().values()),
                                  list(self.target.get_packets_count_by_second().values()))

        values_org = np.array(list(self.original.get_packets_count_by_second().values()))
        values_aug = np.array(list(self.target.get_packets_count_by_second().values()))

        npcumsum_org = np.cumsum(values_org)
        npcumsum_aug = np.cumsum(values_aug)

        self.viz_data["CDF"]["packets_number"] = \
            {
                "x": list(self.original.get_packets_count_by_second().keys()),
                "y1": [float(x/npcumsum_org[-1] if int(npcumsum_org[-1]) != 0 else 0) for x in
                       npcumsum_org],
                "y2": [float(x/npcumsum_aug[-1] if int(npcumsum_aug[-1]) != 0 else 0) for x in
                       npcumsum_aug],
                "xaxis": "Time in second",
                "yaxis": "Packet number"
            }
    def get_earth_mover_distance(self):
        original_deltas = self.original.get_deltas().copy()
        augmented_deltas = self.target.get_deltas().copy()
        bins, histogram_original, histogram_augmented, length_org, length_aug = \
            self.get_data_same_length(original_deltas, augmented_deltas)
        for i in range(len(histogram_original)):
            if length_org != 0:
                histogram_original[i] = histogram_original[i] / length_org
            else:
                break
        for i in range(len(histogram_augmented)):
            if length_org != 0:
                histogram_augmented[i] = histogram_augmented[i] / length_org
            else:
                break
        self.comparisons["Earth_mover_distance"]['Delta'] = stats.wasserstein_distance(histogram_original,
                                                                                       histogram_augmented)

        original_lengths = self.original.get_lengths().copy()
        augmented_lengths = self.target.get_lengths().copy()
        bins, histogram_original, histogram_augmented, length_org, length_aug = \
            self.get_data_same_length(original_lengths, augmented_lengths)
        for i in range(len(histogram_original)):
            if length_org != 0:
                histogram_original[i] = histogram_original[i] / length_org
            else:
                break

        for i in range(len(histogram_augmented)):
            if length_org != 0:
                histogram_augmented[i] = histogram_augmented[i] / length_org
            else:
                break
        self.comparisons["Earth_mover_distance"]['Length'] = stats.wasserstein_distance(histogram_original,
                                                                                        histogram_augmented)

        original_packets_number = list(self.original.get_packets_count_by_second().values()).copy()
        augmented_packets_number = list(self.target.get_packets_count_by_second().values()).copy()

        bins, histogram_original, histogram_augmented, length_org, length_aug = \
            self.get_data_same_length(original_packets_number, augmented_packets_number)
        for i in range(len(histogram_original)):
            if length_org != 0:
                histogram_original[i] = histogram_original[i] / length_org
            else:
                break

        for i in range(len(histogram_augmented)):
            if length_org != 0:
                histogram_augmented[i] = histogram_augmented[i] / length_org
            else:
                break
        self.comparisons["Earth_mover_distance"]['Packet number by second'] =\
            stats.wasserstein_distance(histogram_original, histogram_augmented)

    def get_dynamic_time_warping(self):
        original_deltas = self.original.get_deltas().copy()
        augmented_deltas = self.target.get_deltas().copy()

        bins, histogram_original, histogram_augmented, length_org, length_aug = \
            self.get_data_same_length(original_deltas, augmented_deltas)
        for i in range(len(histogram_original)):
            if length_org != 0:
                histogram_original[i] = histogram_original[i] / length_org
            else:
                break

        for i in range(len(histogram_augmented)):
            if length_org != 0:
                histogram_augmented[i] = histogram_augmented[i] / length_org
            else:
                break
        self.comparisons["Dynamic_time_warping"]['Delta'] = dtw.distance(histogram_original, histogram_augmented)
        original_lengths = self.original.get_lengths().copy()
        augmented_lengths = self.target.get_lengths().copy()

        bins, histogram_original, histogram_augmented, length_org, length_aug = \
            self.get_data_same_length(original_lengths, augmented_lengths)

        for i in range(len(histogram_original)):
            if length_org != 0:
                histogram_original[i] = histogram_original[i] / length_org
            else:
                break

        for i in range(len(histogram_augmented)):
            if length_org != 0:
                histogram_augmented[i] = histogram_augmented[i] / length_org
            else:
                break

        self.comparisons["Dynamic_time_warping"]['Length'] = dtw.distance(histogram_original, histogram_augmented)

        original_packets_number = list(self.original.get_packets_count_by_second().values()).copy()
        augmented_packets_number = list(self.target.get_packets_count_by_second().values()).copy()

        bins, histogram_original, histogram_augmented, length_org, length_aug = \
            self.get_data_same_length(original_packets_number, augmented_packets_number)
        for i in range(len(histogram_original)):
            if length_org != 0:
                histogram_original[i] = histogram_original[i] / length_org
            else:
                break

        for i in range(len(histogram_augmented)):
            if length_org != 0:
                histogram_augmented[i] = histogram_augmented[i] / length_org
            else:
                break
        self.comparisons["Dynamic_time_warping"]['Packet number by second'] = \
            dtw.distance(histogram_original, histogram_augmented)

    def collect_comparisons(self):
        #self.get_graph_distance()
        self.get_chi_squared_test()
        self.get_kolmogorov_smirnov_test()
        self.get_earth_mover_distance()
        self.get_dynamic_time_warping()

    def get_comparisons(self):
        self.collect_comparisons()
        return {f"{Path(self.original.file).name},{Path(self.target.file).name}": {"comparisons": self.comparisons,
                                                                                   "viz": self.viz_data},
                                                                                   }
