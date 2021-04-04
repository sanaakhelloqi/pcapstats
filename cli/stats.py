from src.Pcap import Pcap
import json
import click
from scapy.error import Scapy_Exception


@click.command()
@click.argument("files", nargs=-1)
@click.option("-o", "--output", type=str, default="result.json")
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

    if stats_df_list:
        click.echo(f"Writing results to {output}")
        with open(f"{output}.json", "w") as comp_json:
            json.dump(stats_df_list, comp_json)
    else:
        click.echo("No results generated.")


if __name__ == "__main__":
    stats()
