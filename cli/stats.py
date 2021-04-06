from pathlib import Path
import src.utils as utils

import json
import click
from scapy.error import Scapy_Exception


@click.command()
@click.argument("files", nargs=-1)
@click.option("-o", "--output", type=str, default="result.json")
def stats(files, output):
    stats_dict = {}

    with click.progressbar(files) as _files:
        click.echo("Analysing pcap files...")
        for _file in _files:
            try:
                pcap = utils.read_file(_file)

                if not pcap:
                    click.echo("Can't read file. Skipping…")
                    continue

                stats_dict[Path(_file).name] = pcap.get_stats()
            except Scapy_Exception as e:
                click.echo("Warning: Not a pcap file. Skipping...")
                continue

    if stats_dict:
        click.echo(f"Writing results to {output}")
        with open(f"{output}.json", "w") as stats_out:
            json.dump(stats_dict, stats_out)
    else:
        click.echo("No results generated.")


if __name__ == "__main__":
    stats()
