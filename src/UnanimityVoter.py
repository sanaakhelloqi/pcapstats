class UnanimityVoter:
    def __init__(self, results: dict, thresholds: dict):
        self.results = results
        self.thresholds = thresholds

    def vote(self) -> bool:
        for metric, metric_values in self.results.items():
            for feature, value in metric_values.items():
                # Check if metrics are p-value based metrics
                if metric in ["Chi_squared_test", "Kolmogorov_smirnov_test"]:
                    if value < self.thresholds[metric]:
                        return False
                # Check if metrics are distance based metrics
                elif metric in ["Earth_mover_distance", "Dynamic_time_warping"]:
                    if value > self.thresholds[metric]:
                        return False
        return True
