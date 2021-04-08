from pathlib import Path
import src.utils as utils

import json
import click
from scapy.error import Scapy_Exception
from concurrent.futures import ProcessPoolExecutor
import tqdm


def stats_worker(_file):
    pcap = utils.read_file(_file)
    return _file, pcap.get_stats()


@click.command("stats", help="Calculate statistics for one or more pcap files.")
@click.argument("files", nargs=-1)
@click.option("-o", "--output", type=str, default="stats.json")
@click.option("-p", "--processes", type=int, default=4, help="Maximum amount of concurrent processes.")
def cli_stats(files, output, processes):
    stats_dict = {}

    click.echo("Analysing pcap files...")
    with ProcessPoolExecutor(max_workers=processes) as executor:
        for _file, _stats in list(tqdm.tqdm(executor.map(stats_worker, files), total=len(files))):
            stats_dict[Path(_file).name] = _stats

    if stats_dict:
        click.echo(f"Writing results to {output}")
        with Path(output).open("w") as stats_out:
            json.dump(stats_dict, stats_out)
    else:
        click.echo("No results generated.")


if __name__ == "__main__":
    cli_stats()
