from src.Pcap import Pcap

import click
from scapy.error import Scapy_Exception
import pandas as pd


@click.command()
@click.argument("files", nargs=-1)
@click.option("-o", "--output", type=str, default="result.csv")
def stats(files, output):
    stats_df_list = []

    with click.progressbar(files) as _files:
        click.echo("Analysing pcap files...")
        for _file in _files:
            try:
                pcap = Pcap(_file)
                stats_df_list.append(pcap.get_stats())
            except Scapy_Exception as e:
                click.echo("Warning: Not a pcap file. Skipping...")
                continue

    click.echo(f"Writing results to {output}")
    stats_df = pd.concat(stats_df_list)
    stats_df.to_csv(output, index=False)


if __name__ == "__main__":
    stats()
