from src.Pcap import Pcap

from scipy import stats
import pandas as pd
from pathlib import Path
import numpy as np
import math
from libs import dtw


class Comparator:
    def __init__(self, original: Pcap, target: Pcap, visualize: bool):
        self.original = original
        self.target = target
        self.viz_data = {f"{Path(self.original.file).name},{Path(self.target.file).name}":
            {
                "Frequencies": {},
                "CDF": {}
            }
        }
        self.comparisons = {
            "Original": {"Number of packets": self.original.get_packets_count(),
                         "Download rate in kbit/s": float(self.original.get_download_rate_by_second()),
                         "Upload rate in kbit/s": float(self.original.get_upload_rate_by_second()),
                         "Length of all packets in kbit": float(self.original.get_total_length()),
                         "Total download length in kbit:": float(self.original.get_total_length_downloaded()),
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
                       "Total download length in kbit:": float(self.target.get_total_length_downloaded()),
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
            "Dynamic_time_warping": {}}

    def get_data_chi_squared(self, data_list_ori, data_list_aug):
        n = len(data_list_ori)
        out, bins = pd.qcut(data_list_ori, math.floor(1.88 * n ** (2 / 5)),
                                labels=False, retbins=True, duplicates='drop')

        histogram_original, bin_edges = np.histogram(data_list_ori, bins, range=None, normed=None,
                                                     weights=None, density=None)
        histogram_augmented, bin_edges = np.histogram(data_list_aug, bins, range=None, normed=None,
                                                      weights=None, density=None)
        factor = len(data_list_ori) / len(data_list_aug)
        histogram_augmented = [value * factor for value in histogram_augmented]
        return bins, histogram_original, histogram_augmented

    def get_chi_squared_test(self):
        bins, histogram_original, histogram_augmented = self.get_data_chi_squared(self.original.get_deltas(),
                                                                                  self.target.get_deltas())
        self.comparisons["Chi_squared_test"]['Delta'] = stats.chisquare(histogram_original, histogram_augmented).pvalue
        self.viz_data[f"{Path(self.original.file).name},{Path(self.target.file).name}"]["Frequencies"]["deltas"] = \
            {
                "x": list(bins[:-1]),
                "y1": [float(x) for x in list(histogram_original)],
                "y2": [float(x) for x in list(histogram_augmented)],
                "xaxis": "Deltas in second",
                "yaxis": "Frequencies"
            }
        bins_length, hist_original_length, hist_augmented_length = \
            self.get_data_chi_squared(self.original.get_lengths(), self.target.get_lengths())

        self.comparisons["Chi_squared_test"]['Length'] = \
            stats.chisquare(hist_augmented_length, hist_original_length).pvalue

        self.viz_data[f"{Path(self.original.file).name},{Path(self.target.file).name}"]["Frequencies"]["lengths"] = \
            {
                "x": list(bins_length[:-1]),
                "y1": [float(x) for x in list(hist_original_length)],
                "y2": [float(x) for x in list(hist_augmented_length)],
                "xaxis": "Lengths in bytes",
                "yaxis": "Frequencies"
            }

        bins_packets_seconds, hist_packets_second, hist_augmented_packets_seconds = \
            self.get_data_chi_squared(self.original.get_packets_count_by_second(),
                                      self.target.get_packets_count_by_second())

        self.comparisons["Chi_squared_test"]['Packet number by second'] = \
            stats.chisquare(hist_augmented_packets_seconds, hist_packets_second).pvalue

        self.viz_data[f"{Path(self.original.file).name},{Path(self.target.file).name}"]["Frequencies"][
            "packets_number"] = \
            {
                "x": list(bins_packets_seconds[:-1]),
                "y1": [float(x) for x in list(hist_packets_second)],
                "y2": [float(x) for x in list(hist_augmented_packets_seconds)],
                "xaxis": "Packets number by second",
                "yaxis": "Frequencies"
            }

    def get_data_KS_test(self, data_list_ori, data_list_aug):
        out, bins = pd.qcut(data_list_ori, math.floor(1.88 * len(data_list_ori) ** (2 / 5)), labels=False, retbins=True,
                            duplicates='drop')
        hist, bin_edges = np.histogram(data_list_ori, bins, range=None, normed=None, weights=None, density=None)
        hist2, bin_edges = np.histogram(data_list_aug, bins, range=None, normed=None, weights=None, density=None)
        return bins, np.cumsum(hist), np.cumsum(hist2)

    def get_kolmogorov_smirnov_test(self):
        self.comparisons["Kolmogorov_smirnov_test"]['Deltas'] = stats.ks_2samp(self.target.get_deltas(),
                                                                               self.original.get_deltas()).pvalue
        self.comparisons["Kolmogorov_smirnov_test"]['Length'] = stats.ks_2samp(self.target.get_lengths(),
                                                                               self.original.get_lengths()).pvalue
        self.comparisons["Kolmogorov_smirnov_test"]['Packet number by second'] = \
            stats.ks_2samp(self.target.get_packets_count_by_second(),
                           self.original.get_packets_count_by_second()).pvalue

        bins, cumulative_original, cumulative_augmented = self.get_data_KS_test(self.original.get_deltas(),
                                                                                self.target.get_deltas())
        self.viz_data[f"{Path(self.original.file).name},{Path(self.target.file).name}"]["CDF"]["deltas"] = \
            {
                "x": list(bins[:-1]),
                "y1": [float(x) for x in list(cumulative_original)],
                "y2": [float(x) for x in list(cumulative_augmented)],
                "xaxis": "Deltas in second",
                "yaxis": "Number of packets"
            }

        bins_lengths, hist_lengths, hist2_lengths = self.get_data_KS_test(self.original.get_lengths(),
                                                                          self.target.get_lengths())
        self.viz_data[f"{Path(self.original.file).name},{Path(self.target.file).name}"]["CDF"]["lengths"] = \
            {
                "x": list(bins_lengths[:-1]),
                "y1": [float(x) for x in list(hist_lengths)],
                "y2": [float(x) for x in list(hist2_lengths)],
                "xaxis": "Lengths in bytes",
                "yaxis": "Number of packets"
            }

        bins_packet_number, hist_packet_number, hist2_packet_number = \
            self.get_data_KS_test(self.original.get_packets_count_by_second(),
                                  self.target.get_packets_count_by_second())
        self.viz_data[f"{Path(self.original.file).name},{Path(self.target.file).name}"]["CDF"]["packets_number"] = \
            {
                "x": list(bins_packet_number[:-1]),
                "y1": [float(x) for x in list(hist_packet_number)],
                "y2": [float(x) for x in list(hist2_packet_number)],
                "xaxis": "Packet number by second",
                "yaxis": "Seconds"
            }

    def get_earth_mover_distance(self):
        self.comparisons["Earth_mover_distance"]['Delta'] = \
            stats.wasserstein_distance(self.original.get_deltas(), self.target.get_deltas())
        self.comparisons["Earth_mover_distance"]['Length'] = \
            stats.wasserstein_distance(self.original.get_lengths(), self.target.get_lengths())
        self.comparisons["Earth_mover_distance"]['Packet number by second'] = \
            stats.wasserstein_distance(self.original.get_packets_count_by_second(),
                                       self.target.get_packets_count_by_second())

    def get_dynamic_time_warping(self, plot=True):
        _dtw = dtw.dtw(self.original.get_deltas(), self.target.get_deltas(), keep_internals=True)
        self.comparisons["Dynamic_time_warping"]['Delta'] = _dtw.distance

        _dtw_length = dtw.dtw(self.original.get_lengths(), self.target.get_lengths(), keep_internals=True)
        self.comparisons["Dynamic_time_warping"]['Length'] = _dtw_length.distance

        _dtw_packet_second = dtw.dtw(self.original.get_packets_count_by_second(),
                                     self.target.get_packets_count_by_second(), keep_internals=True)
        self.comparisons["Dynamic_time_warping"]['Packet number by second'] = _dtw_packet_second.distance

    def collect_comparisons(self):
        self.get_chi_squared_test()
        self.get_kolmogorov_smirnov_test()
        self.get_earth_mover_distance()
        self.get_dynamic_time_warping()

    def get_comparisons(self):
        self.collect_comparisons()
        return self.comparisons, self.viz_data
