from src.PacketCapture import PacketCapture

from pathlib import Path
import math

from dtaidistance import dtw
from scipy import stats
import pandas as pd
from networkx.readwrite import json_graph
import numpy as np

np.seterr(divide='ignore', invalid='ignore')


class Comparator:
    def __init__(self, original: PacketCapture, target: PacketCapture):
        self.original = original
        self.target = target

        self.original_filename = Path(original.file).name
        self.target_filename = Path(target.file).name

        self.viz = {
            "Frequencies": {},
            "CDF": {}
        }

        self.graphs = {
            self.original_filename: json_graph.node_link_data(self.original.get_ip_graph()),
            self.target_filename: json_graph.node_link_data(self.target.get_ip_graph())
        }

        self.features = {}

        self.comparisons = {
            "Chi_squared_test": {},
            "Kolmogorov_smirnov_test": {},
            "Earth_mover_distance": {},
            "Dynamic_time_warping": {},
        }

    @staticmethod
    def get_data_same_length(data_list_ori, data_list_aug):
        n = len(data_list_ori)
        if n < 30:
            out, bins = pd.qcut(data_list_ori, n,
                                labels=False, retbins=True, duplicates='drop')
        else:
            out, bins = pd.qcut(data_list_ori, math.ceil(math.log2(n)) + 1,
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
        bins, histogram_original, histogram_augmented, length_org, length_aug = \
            self.get_data_same_length(data_list_ori, data_list_aug)
        return bins, histogram_original, histogram_augmented

    def get_cdf_data(self, data_list_ori, data_list_aug):
        bins, histogram_original, histogram_augmented, length_org, length_aug = \
            self.get_data_same_length(data_list_ori, data_list_aug)
        return bins, np.cumsum(histogram_original), np.cumsum(histogram_augmented), length_org, length_aug

    def get_chi_squared_test_deltas(self):
        bins, histogram_original, histogram_augmented = self.get_data_chi_squared(self.original.get_deltas(),
                                                                                  self.target.get_deltas())
        self.comparisons["Chi_squared_test"]["Delta"] = stats.chisquare(histogram_original, histogram_augmented).pvalue

        self.viz["Frequencies"]["Delta"] = \
            {
                "x": list(bins[:-1]),
                "y1": [float(x) for x in list(histogram_original)],
                "y2": [float(x) for x in list(histogram_augmented)],
                "xaxis": "Deltas in second",
                "yaxis": "Packet number"
            }

    def get_chi_squared_test_lengths(self):
        bins_length, hist_original_length, hist_augmented_length = \
            self.get_data_chi_squared(self.original.get_lengths(), self.target.get_lengths())

        self.comparisons["Chi_squared_test"]["Length"] = \
            stats.chisquare(hist_augmented_length, hist_original_length).pvalue

        self.viz["Frequencies"]["Length"] = \
            {
                "x": list(bins_length[:-1]),
                "y1": [float(x) for x in list(hist_original_length)],
                "y2": [float(x) for x in list(hist_augmented_length)],
                "xaxis": "Lengths in bytes",
                "yaxis": "Packet number"
            }

    def get_chi_squared_test_packets_number(self):
        bins_packets_seconds, hist_packets_second, hist_augmented_packets_seconds = \
            self.get_data_chi_squared(list(self.original.get_packets_count_by_second().values()),
                                      list(self.target.get_packets_count_by_second().values()))

        self.comparisons["Chi_squared_test"]['Packet number by second'] = \
            stats.chisquare(hist_augmented_packets_seconds, hist_packets_second).pvalue

        self.viz["Frequencies"]["Packet number by second"] = \
            {
                "x": list(self.original.get_packets_count_by_second().keys()),
                "y1": [float(x) for x in list(self.original.get_packets_count_by_second().values())],
                "y2": [float(x) for x in list(self.target.get_packets_count_by_second().values())],
                "xaxis": "Time in seconds",
                "yaxis": "Packet number"
            }

    def get_kolmogorov_smirnov_test_deltas(self):
        self.comparisons["Kolmogorov_smirnov_test"]["Delta"] = stats.ks_2samp(self.target.get_deltas(),
                                                                              self.original.get_deltas()).pvalue

        bins, cumulative_original, cumulative_augmented, histmax, hist2max = self.get_cdf_data(
            self.original.get_deltas(),
            self.target.get_deltas())

        self.viz["CDF"]["Delta"] = \
            {
                "x": list(bins[:-1]),
                "y1": [float(x / histmax if int(histmax) != 0 else x) for x in list(cumulative_original)],
                "y2": [float(x / hist2max if int(hist2max) != 0 else x) for x in list(cumulative_augmented)],
                "xaxis": "Deltas in second",
                "yaxis": "Number of packets"
            }

    def get_kolmogorov_smirnov_test_lengths(self):
        self.comparisons["Kolmogorov_smirnov_test"]["Length"] = stats.ks_2samp(self.target.get_lengths(),
                                                                               self.original.get_lengths()).pvalue

        bins_lengths, hist_lengths, hist2_lengths, histmax, hist2max = self.get_cdf_data(self.original.get_lengths(),
                                                                                         self.target.get_lengths())
        self.viz["CDF"]["Length"] = \
            {
                "x": list(bins_lengths[:-1]),
                "y1": [float(x / histmax if int(histmax) != 0 else x) for x in list(hist_lengths)],
                "y2": [float(x / hist2max if int(hist2max) != 0 else x) for x in list(hist2_lengths)],
                "xaxis": "Lengths in bytes",
                "yaxis": "Number of packets"
            }

    def get_kolmogorov_smirnov_test_packet_number(self):
        self.comparisons["Kolmogorov_smirnov_test"]['Packet number by second'] = \
            stats.ks_2samp(list(self.target.get_packets_count_by_second().values()),
                           list(self.original.get_packets_count_by_second().values())).pvalue
        values_org = np.array(list(self.original.get_packets_count_by_second().values()))
        values_aug = np.array(list(self.target.get_packets_count_by_second().values()))

        npcumsum_org = np.cumsum(values_org)
        npcumsum_aug = np.cumsum(values_aug)

        self.viz["CDF"]["Packet number by second"] = \
            {
                "x": list(self.original.get_packets_count_by_second().keys()),
                "y1": [float(x / npcumsum_org[-1] if int(npcumsum_org[-1]) != 0 else 0) for x in
                       npcumsum_org],
                "y2": [float(x / npcumsum_aug[-1] if int(npcumsum_aug[-1]) != 0 else 0) for x in
                       npcumsum_aug],
                "xaxis": "Time in second",
                "yaxis": "Packet number"
            }

    @staticmethod
    def get_data_normalized(original_data, augmented_data):
        max_org = max(original_data)
        min_org = min(original_data)
        max_aug = max(augmented_data)
        min_aug = min(augmented_data)
        augmented_data_len = len(augmented_data)
        original_data_len = len(original_data)

        for i in range(original_data_len):
            if max_org - min_org != 0:
                original_data[i] = (original_data[i] - min_org) / (max_org - min_org)
            else:
                original_data[i] = 1 / original_data_len
        for i in range(augmented_data_len):
            if max_aug - min_aug != 0:
                augmented_data[i] = (augmented_data[i] - min_aug) / (max_aug - min_aug)
            else:
                augmented_data[i] = 1 / augmented_data_len
        return original_data, augmented_data

    def get_earth_mover_distance_deltas(self):
        original_deltas = self.original.get_deltas().copy()
        augmented_deltas = self.target.get_deltas().copy()
        original_deltas, augmented_deltas = self.get_data_normalized(original_deltas, augmented_deltas)
        self.comparisons["Earth_mover_distance"]["Delta"] = stats.wasserstein_distance(original_deltas,
                                                                                       augmented_deltas)

    def get_earth_mover_distance_lengths(self):
        original_lengths = self.original.get_lengths().copy()
        augmented_lengths = self.target.get_lengths().copy()
        original_lengths, augmented_lengths = self.get_data_normalized(original_lengths, augmented_lengths)
        self.comparisons["Earth_mover_distance"]["Length"] = stats.wasserstein_distance(original_lengths,
                                                                                        augmented_lengths)

    def get_earth_mover_distance_packets_number(self):
        original_packets_number = list(self.original.get_packets_count_by_second().values()).copy()
        augmented_packets_number = list(self.target.get_packets_count_by_second().values()).copy()
        original_packets_number, augmented_packets_number = self.get_data_normalized(original_packets_number,
                                                                                     augmented_packets_number)
        self.comparisons["Earth_mover_distance"]['Packet number by second'] = \
            stats.wasserstein_distance(original_packets_number, augmented_packets_number)

    def get_dynamic_time_warping_deltas(self):
        original_deltas = self.original.get_deltas().copy()
        augmented_deltas = self.target.get_deltas().copy()
        original_deltas, augmented_deltas = self.get_data_normalized(original_deltas, augmented_deltas)
        self.comparisons["Dynamic_time_warping"]["Delta"] = dtw.distance(original_deltas, augmented_deltas)

    def get_dynamic_time_warping_lengths(self):
        original_lengths = self.original.get_lengths().copy()
        augmented_lengths = self.target.get_lengths().copy()
        original_lengths, augmented_lengths = self.get_data_normalized(original_lengths, augmented_lengths)
        self.comparisons["Dynamic_time_warping"]["Length"] = dtw.distance(original_lengths, augmented_lengths)

    def get_dynamic_time_warping_packets_number(self):
        original_packets_number = list(self.original.get_packets_count_by_second().values()).copy()
        augmented_packets_number = list(self.target.get_packets_count_by_second().values()).copy()
        original_packets_number, augmented_packets_number = self.get_data_normalized(original_packets_number,
                                                                                     augmented_packets_number)
        self.comparisons["Dynamic_time_warping"]['Packet number by second'] = \
            dtw.distance(original_packets_number, augmented_packets_number)

    def calculate_metrics(self):
        # self.get_graph_distance()
        # self.get_chi_squared_test()
        self.get_chi_squared_test_deltas()
        self.get_chi_squared_test_lengths()
        self.get_chi_squared_test_packets_number()

        # self.get_kolmogorov_smirnov_test()
        self.get_kolmogorov_smirnov_test_deltas()
        self.get_kolmogorov_smirnov_test_lengths()
        self.get_kolmogorov_smirnov_test_packet_number()

        self.get_earth_mover_distance_deltas()
        self.get_earth_mover_distance_lengths()
        self.get_earth_mover_distance_packets_number()

        self.get_dynamic_time_warping_deltas()
        self.get_dynamic_time_warping_lengths()
        self.get_dynamic_time_warping_packets_number()

    def get_features(self):
        return self.features

    def calc_features(self):
        self.features = {self.original_filename: {"Number of packets": self.original.get_packets_count(),
                                                  "Download rate in kbit/s": float(
                                                      self.original.get_download_rate_by_second()),
                                                  "Upload rate in kbit/s": float(
                                                      self.original.get_upload_rate_by_second()),
                                                  "Length of all packets in kbit": float(
                                                      self.original.get_total_length()),
                                                  "Total downloaded length in kbit": float(
                                                      self.original.get_total_length_downloaded()),
                                                  "Total Stall time": float(
                                                      self.original.get_total_stall_time(30, 8000)),
                                                  "Total Stall number": float(
                                                      self.original.get_total_stall_count(30, 8000)),
                                                  "Initial delay": float(self.original.get_initial_delay(30, 8000)),
                                                  "Time needed in second for the total downloaded size":
                                                      float(self.original.get_page_load_time_total()),
                                                  "Time needed for the half of the downloaded size":
                                                      float(self.original.get_page_load_time_half()),
                                                  "Time needed for the quarter of the downloaded size": float(
                                                      self.original.get_page_load_time_quarter()),
                                                  "Time needed for the three quarters of the downloaded size": float(
                                                      self.original.get_page_load_time_three_quarters())
                                                  },
                         self.target_filename: {"Number of packets": self.target.get_packets_count(),
                                                "Download rate in kbit/s": float(
                                                    self.target.get_download_rate_by_second()),
                                                "Upload rate in kbit/s": float(self.target.get_upload_rate_by_second()),
                                                "Length of all packets in kbit": float(self.target.get_total_length()),
                                                "Total downloaded length in kbit": float(
                                                    self.target.get_total_length_downloaded()),
                                                "Total Stall time": float(self.target.get_total_stall_time(30, 8000)),
                                                "Total Stall number": float(self.target.get_total_stall_count(30, 8000)),
                                                "Initial delay": float(self.target.get_initial_delay(30, 8000)),
                                                "Time needed in second for the total downloaded size": float(
                                                    self.target.get_page_load_time_total()),
                                                "Time needed for the half of the downloaded size": float(
                                                    self.target.get_page_load_time_half()),
                                                "Time needed for the quarter of downloaded size": float(
                                                    self.target.get_page_load_time_quarter()),
                                                "Time needed for the three quarters of the downloaded size": float(
                                                    self.target.get_page_load_time_three_quarters())
                                                }
                         }

    def get_comparisons(self, raw=False):
        if raw:
            return self.comparisons
        return {f"{self.original_filename},{self.target_filename}": {"metrics": self.comparisons,
                                                                     "visualization_data": self.viz}}

    def get_graphs(self):
        return self.graphs
