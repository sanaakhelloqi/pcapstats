from scipy import stats
import pandas as pd
from pathlib import Path
import src.utils as utils
import numpy as np
import math
from libs import dtw
import matplotlib.pyplot as plt

class Comparator:
    def __init__(self, original, target, visualize: bool):
        self.original = original
        self.target = target
        self.comparisons = {"original": self.original.stats["pcap"],
                            "target": self.target.stats["pcap"]}
        self.visualize = visualize
        self.pdf_output = []

    def get_chi_squared_test(self):
        out, bins = pd.qcut(self.original.deltas, math.floor(1.88 * len(self.original.deltas) ** (2 / 5)), labels=False, retbins=True,
                            duplicates='drop')
        hist, bin_edges = np.histogram(self.original.deltas, bins, range=None, normed=None, weights=None, density=None)
        hist2, bin_edges = np.histogram(self.target.deltas, bins, range=None, normed=None, weights=None, density=None)
        self.comparisons["chi_squared_test"] = stats.chisquare(hist2, f_exp=hist).pvalue

        if self.visualize:
            out_chisquare = f"chisquare_{utils.get_basename(Path(self.comparisons['original']))}_{utils.get_basename(Path(self.comparisons['target']))}.pdf"
            plt.hist(bins[:-1], bins, weights=hist, label='Original deltas')
            plt.hist(bins[:-1], bins, weights=hist2, label='Augmented deltas')
            plt.title("Häufigkeiten für originale und augmentierte Daten")
            plt.legend(loc='upper right')
            plt.xlabel("Deltas in Sekunden")
            plt.ylabel("Häufigkeiten")
            plt.savefig(out_chisquare)
            self.pdf_output.append(out_chisquare)
            plt.clf()



    def get_kolmogorov_smirnov_test(self):
        out, bins = pd.qcut(self.original.deltas, math.floor(1.88 * len(self.original.deltas) ** (2 / 5)), labels=False,
                            retbins=True,
                            duplicates='drop')
        hist, bin_edges = np.histogram(self.original.deltas, bins, range=None, normed=None, weights=None, density=None)
        hist2, bin_edges = np.histogram(self.target.deltas, bins, range=None, normed=None, weights=None, density=None)
        self.comparisons["kolmogorov_smirnov_test"] = stats.ks_2samp(self.target.deltas,
                                                                     self.original.deltas).pvalue
        if self.visualize:
            out_KS= f"KS_{utils.get_basename(Path(self.comparisons['original']))}_{utils.get_basename(Path(self.comparisons['target']))}.pdf"
            cumulative_original = np.cumsum(hist)
            cumulative_augmented = np.cumsum(hist2)
            plt.plot(bins[:-1], cumulative_original, c='blue', label='Original deltas')
            plt.plot(bins[:-1], cumulative_augmented, c='green', label='Augmented deltas')
            plt.title("Kumulative Verteilungen für originale und augmentierte Daten")
            plt.xlabel("Deltas in Sekunden")
            plt.ylabel("Paketanzahl")
            plt.legend(loc='lower right')
            plt.savefig(out_KS)
            self.pdf_output.append(out_KS)
            plt.clf()

    def get_earth_mover_distance(self):
        self.comparisons["earth_mover_distance"] = stats.wasserstein_distance(self.original.deltas, self.target.deltas)

    def get_dynamic_time_warping(self, plot = True):
        _dtw = dtw.dtw(self.original.deltas, self.target.deltas, keep_internals=True)
        self.comparisons["dynamic_time_warping"] = _dtw.distance

        if self.visualize:
            out = f"dtw_{utils.get_basename(Path(self.comparisons['original']))}_{utils.get_basename(Path(self.comparisons['target']))}.pdf"
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
        return pd.DataFrame(self.comparisons, index=[0]), self.pdf_output





