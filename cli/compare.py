from src.Pcap import Pcap
from src.Comparator import Comparator

import click
from scapy.error import Scapy_Exception
import pandas as pd


@click.command()
@click.argument("original", nargs=1)
@click.argument("targets", nargs=-1)
@click.option("-o", "--output", type=str, default="result.csv")
def compare(original, targets, output):
    comparison_df_list = []

    with click.progressbar(targets) as _targets:
        click.echo("Comparing pcap files...")
        original_pcap = Pcap(original)

        for target in _targets:
            try:
                target_pcap = Pcap(target)
            except Scapy_Exception:
                click.echo("Warning: Not a valid pcap file. Skipping...")
                continue

            comp_df = Comparator(original_pcap, target_pcap).get_comparisons()
            comparison_df_list.append(comp_df)

    if comparison_df_list:
        click.echo(f"Writing results to {output}")
        stats_df = pd.concat(comparison_df_list)
        stats_df.to_csv(output, index=False)
    else:
        click.echo("No results generated.")


if __name__ == "__main__":
    compare()
