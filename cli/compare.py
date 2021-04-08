import src.utils as utils
from src.Comparator import Comparator
from src.visualize import visualize as viz

from concurrent.futures import ProcessPoolExecutor
import tqdm
from pathlib import Path

import json
import click


def comparison_wrapper(data):
    return comparison_worker(*data)


def comparison_worker(original, target):
    stats = target.get_stats()

    comp = Comparator(original, target)
    comp.calc_features()
    comp.calculate_metrics()

    return target, stats, comp


@click.command("compare", help="Calculate similarity metrics and statistics for one or more pcap file.")
@click.argument("original", nargs=1)
@click.argument("targets", nargs=-1)
@click.option("-o", "--output", type=str, default="compare.json")
@click.option("-v", "--visualize", is_flag=True)
@click.option("-vo", "--visualize-output", type=str, default="result.html")
@click.option("-p", "--processes", type=int, default=4, help="Maximum amount of concurrent processes.")
def cli_compare(original, targets, output, visualize, visualize_output, processes):
    feature_dict = {}
    comparison_dict = {}
    stats_dict = {}
    graph_dict = {}

    click.echo("Comparing pcap files...")
    original_pcap = utils.read_file(original)

    stats_dict[Path(original).name] = original_pcap.get_stats()

    if not original_pcap:
        click.echo("No valid file type supplied. Aborting…")
        return

    zipped_targets = [[original_pcap, target_pcap] for target_pcap in [utils.read_file(target) for target in targets]]

    with ProcessPoolExecutor(max_workers=processes) as executor:
        for _target, _stats, _comp_results in list(tqdm.tqdm(executor.map(comparison_wrapper, zipped_targets),
                                                             total=len(zipped_targets))):
            stats_dict[Path(_target.file).name] = _stats
            feature_dict = {**feature_dict, **_comp_results.get_features()}
            comparison_dict = {**comparison_dict, **_comp_results.get_comparisons()}
            graph_dict = {**graph_dict, **_comp_results.get_graphs()}

    export_dict = {"comparisons": comparison_dict, "features": feature_dict, "graphs": graph_dict, "stats": stats_dict}

    if comparison_dict:
        click.echo(f"Writing results to {output}")
        with open(output, "w") as comp_json:
            json.dump(export_dict, comp_json)
    else:
        click.echo("No results generated.")

    if visualize:
        if not export_dict["comparisons"]:
            click.echo("Empty List.")
        else:
            viz(export_dict, visualize_output)


if __name__ == "__main__":
    cli_compare()
