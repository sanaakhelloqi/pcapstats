from scipy import stats
import pandas as pd


class Comparator:
    def __init__(self, original, target):
        self.original = original
        self.target = target
        self.comparisons = {"original": self.original.stats["pcap"],
                            "target": self.target.stats["pcap"]}

    def get_chi_squared_test(self):
        self.comparisons["chi_squared_test"] = stats.chisquare(self.target.deltas[1:],
                                                               f_exp=self.original.deltas[1:]).statistic

    def get_kolmogorov_smirnov_test(self):
        self.comparisons["kolmogorov_smirnov_test"] = stats.ks_2samp(self.target.deltas,
                                                                     self.original.deltas).statistic

    def get_earth_mover_distance(self):
        self.comparisons["earth_mover_distance"] = stats.wasserstein_distance(self.original.deltas, self.target.deltas)

    def collect_comparisons(self):
        self.get_chi_squared_test()
        self.get_kolmogorov_smirnov_test()
        self.get_earth_mover_distance()

    def get_comparisons(self):
        self.collect_comparisons()
        return pd.DataFrame(self.comparisons, index=[0])
