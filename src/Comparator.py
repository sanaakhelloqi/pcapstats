from src.Pcap import Pcap

from scipy import stats
import pandas as pd
from pathlib import Path
import src.utils as utils
import numpy as np
import math
from libs import dtw
import matplotlib.pyplot as plt


class Comparator:
    def __init__(self, original: Pcap, target:  Pcap, visualize: bool):
        self.original = original
        self.target = target
        self.comparisons = {"Original": {"Number of packets in OrgFile": self.original.get_packets_count(),
                                         "Download rate in kbps": float(self.original.get_download_rate_by_second()),
                                         "Upload rate in kbps": float(self.original.get_upload_rate_by_second()),
                                         "Length of all packets in kbits": float(self.original.get_total_length_in_mbit())},
                            "Target": {"Number of packets in testFile": self.target.get_packets_count(),
                                       "Download rate in kbps": float(self.target.get_download_rate_by_second()),
                                       "Upload rate in kbps": float(self.target.get_upload_rate_by_second()),
                                       "Length of all packets in kbits" :float(self.original.get_total_length_in_mbit())
                                       },
                            "Chi_squared_test": {},
                            "Kolmogorov_smirnov_test": {},
                            "Earth_mover_distance": {},
                            "Dynamic_time_warping": {}}
        
        self.visualize = visualize
        self.pdf_output = []

    def get_chi_squared_test(self):
        out, bins = pd.qcut(self.original.get_deltas(), math.floor(1.88 * len(self.original.get_deltas()) ** (2 / 5)), labels=False, retbins=True, duplicates='drop')
        histogram_original, bin_edges = np.histogram(self.original.get_deltas(), bins, range=None, normed=None, weights=None, density=None)
        histogram_augmented, bin_edges = np.histogram(self.target.get_deltas(), bins, range=None, normed=None, weights=None, density=None)
        factor = len(self.original.get_deltas())/len(self.target.get_deltas())
        histogram_augmented = [value * factor for value in histogram_augmented]
        self.comparisons["Chi_squared_test"]['Delta'] = stats.chisquare(histogram_original, histogram_augmented).pvalue

        out, bins_length = pd.qcut(self.original.get_lengths(), math.floor(1.88 * len(self.original.get_lengths()) ** (2 / 5)), labels=False, retbins=True, duplicates='drop')
        hist_original_length, bin_edges = np.histogram(self.original.get_lengths(), bins_length, range=None, normed=None, weights=None, density=None)
        hist_augmented_length, bin_edges = np.histogram(self.target.get_lengths(), bins_length, range=None, normed=None, weights=None,density=None)
        self.comparisons["Chi_squared_test"]['Length'] = stats.chisquare(hist_augmented_length, hist_original_length).pvalue

        out, bins_packets_seconds = pd.qcut(self.original.get_packets_count_by_second(),math.floor(1.88 * len(self.original.get_packets_count_by_second()) ** (2 / 5)), labels=False,retbins=True, duplicates='drop')
        hist_packets_second, bin_edges = np.histogram(self.original.get_packets_count_by_second(), bins_packets_seconds, range=None, normed=None,weights=None, density=None)
        hist_augmented_packets_seconds, bin_edges = np.histogram(self.target.get_packets_count_by_second(), bins_packets_seconds, range=None, normed=None, weights=None, density=None)
        self.comparisons["Chi_squared_test"]['Packet number by second'] = stats.chisquare(hist_augmented_packets_seconds, hist_packets_second).pvalue

        if self.visualize:
            out_chisquare = f"chisquare_{utils.get_basename(Path(self.comparisons['Original']['Path']))}_{utils.get_basename(Path(self.comparisons['target']['Path']))}.pdf"
            plt.hist(bins[:-1], bins, weights=histogram_original, label='Original deta')
            plt.hist(bins[:-1], bins, weights=histogram_augmented, label='Augmented data')
            plt.title("Frequencies for original and augmented data")
            plt.legend(loc='upper right')
            plt.xlabel("Deltas in seconds")
            plt.ylabel("Frequencies")
            plt.savefig(out_chisquare)
            self.pdf_output.append(out_chisquare)
            plt.clf()

    def get_kolmogorov_smirnov_test(self):
        out, bins = pd.qcut(self.original.get_deltas(), math.floor(1.88 * len(self.original.get_deltas()) ** (2 / 5)), labels=False, retbins=True, duplicates='drop')
        hist, bin_edges = np.histogram(self.original.get_deltas(), bins, range=None, normed=None, weights=None, density=None)
        hist2, bin_edges = np.histogram(self.target.get_deltas(), bins, range=None, normed=None, weights=None, density=None)
        self.comparisons["Kolmogorov_smirnov_test"]['Deltas'] = stats.ks_2samp(self.target.get_deltas(), self.original.get_deltas()).pvalue


        self.comparisons["Kolmogorov_smirnov_test"]['Length'] = stats.ks_2samp(self.target.get_lengths(), self.original.get_lengths()).pvalue
        self.comparisons["Kolmogorov_smirnov_test"]['Packet number by second'] = stats.ks_2samp(self.target.get_packets_count_by_second(),
                                                                               self.original.get_packets_count_by_second()).pvalue

        if self.visualize:
            out_KS= f"KS_{utils.get_basename(Path(self.comparisons['Original']['Path']))}_{utils.get_basename(Path(self.comparisons['Target']['Path']))}.pdf"
            cumulative_original = np.cumsum(hist)
            cumulative_augmented = np.cumsum(hist2)
            plt.plot(bins[:-1], cumulative_original, c='blue', label='Original data')
            plt.plot(bins[:-1], cumulative_augmented, c='green', label='Augmented data')
            plt.title("Cumulative distributions for original and augmented data")
            plt.xlabel("Deltas in seconds")
            plt.ylabel("Number of packets")
            plt.legend(loc='lower right')
            plt.savefig(out_KS)
            self.pdf_output.append(out_KS)
            plt.clf()

    def get_earth_mover_distance(self):
        self.comparisons["Earth_mover_distance"]['Delta'] = stats.wasserstein_distance(self.original.get_deltas(), self.target.get_deltas())
        self.comparisons["Earth_mover_distance"]['Length'] = stats.wasserstein_distance(self.original.get_lengths(), self.target.get_lengths())
        self.comparisons["Earth_mover_distance"]['Packet number by second'] = stats.wasserstein_distance(self.original.get_packets_count_by_second(), self.target.get_packets_count_by_second())

    def get_dynamic_time_warping(self, plot=True):
        _dtw = dtw.dtw(self.original.get_deltas(), self.target.get_deltas(), keep_internals=True)
        self.comparisons["Dynamic_time_warping"]['Delta'] = _dtw.distance

        _dtw_length = dtw.dtw(self.original.get_lengths(), self.target.get_lengths(), keep_internals=True)
        self.comparisons["Dynamic_time_warping"]['Length'] = _dtw_length.distance

        _dtw_packet_second = dtw.dtw(self.original.get_packets_count_by_second(), self.target.get_packets_count_by_second(), keep_internals=True)
        self.comparisons["Dynamic_time_warping"]['Packet number by second'] = _dtw_packet_second.distance

        if self.visualize:
            out = f"dtw_{utils.get_basename(Path(self.comparisons['Original']['Path']))}_{utils.get_basename(Path(self.comparisons['target']['Path']))}.pdf"
            fig = _dtw.plot(type="threeway", offset=-2).get_figure()
            fig.savefig(out)
            plt.close(fig)
            self.pdf_output.append(out)

    def collect_comparisons(self):
        self.get_chi_squared_test()
        self.get_kolmogorov_smirnov_test()
        self.get_earth_mover_distance()
        self.get_dynamic_time_warping()


    def get_comparisons(self):
        self.collect_comparisons()
        return self.comparisons, self.pdf_output





