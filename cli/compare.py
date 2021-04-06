import src.utils as utils
from src.Comparator import Comparator
from src.visualize import visualize as viz

from pathlib import Path

import json
import click


@click.command()
@click.argument("original", nargs=1)
@click.argument("targets", nargs=-1)
@click.option("-o", "--output", type=str, default="result.json")
@click.option("-v", "--visualize", is_flag=True)
@click.option("-vo", "--visualize-output", type=str, default="result.html")
def compare(original, targets, output, visualize, visualize_output):
    feature_dict = {}
    comparison_dict = {}
    stats_dict = {}
    graph_dict = {}

    with click.progressbar(targets) as _targets:
        click.echo("Comparing pcap files...")
        original_pcap = utils.read_file(original)

        stats_dict[Path(original).name] = original_pcap.get_stats()

        if not original_pcap:
            click.echo("No valid file type supplied. Aborting…")
            return

        for target in _targets:
            target_pcap = utils.read_file(target)

            if not target_pcap:
                click.echo("Can't read file. Skipping…")
                continue

            stats_dict[Path(target).name] = target_pcap.get_stats()
            comparator = Comparator(original_pcap, target_pcap)

            comparator.calculate()

            feature_dict = {**feature_dict, **comparator.get_features()}
            comparison_dict = {**comparison_dict, **comparator.get_comparisons()}
            graph_dict = {**graph_dict, **comparator.get_graphs()}

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
    compare()


