import src.utils as utils
from src.Sieve import Sieve

from pathlib import Path
import click
import json
from concurrent.futures import ProcessPoolExecutor
import tqdm


def filter_target_wrapper(data):
    return filter_target(*data)


def filter_target(target, original_pcap, json_file):
    target_pcap = utils.read_file(target)

    if not target_pcap:
        click.echo("Can't read file. Skipping…")
        raise Exception

    similarity_filter = Sieve(original_pcap, target_pcap, json_file)

    return target, similarity_filter.sieve()


@click.command("filter", help="Filter pcap files based on similarity metrics.")
@click.argument("original", nargs=1)
@click.argument("targets", nargs=-1)
@click.option("-o", "--output", default="filter.json", help="File where filter output gets saved.")
@click.option("-j", "--json-file", help="JSON containing custom thresholds for the available metrics.")
@click.option("-p", "--processes", type=int, default=4, help="Maximum amount of concurrent processes.")
def cli_filter(original, targets, output, json_file, processes):
    similar = []
    dissimilar = []

    click.echo("Comparing pcap files...")
    original_pcap = utils.read_file(original)

    if not original_pcap:
        click.echo("No valid file type supplied. Aborting…")
        return

    zipped_targets = [[target, original_pcap, json_file] for target in targets]

    with ProcessPoolExecutor(max_workers=processes) as executor:
        for _target, _filter_result in list(tqdm.tqdm(executor.map(filter_target_wrapper, zipped_targets),
                                                      total=len(zipped_targets))):
            if _filter_result:
                similar.append(_target)
            else:
                dissimilar.append(_target)

    with Path(output).open("w") as outfile:
        out_dict = {"original": original, "similar": similar, "dissimilar": dissimilar}
        json.dump(out_dict, outfile)


if __name__ == "__main__":
    cli_filter()
