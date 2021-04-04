from src.Pcap import Pcap
from src.Comparator import Comparator
from src.visualize import visualize as viz


import json
import click
from scapy.error import Scapy_Exception


@click.command()
@click.argument("original", nargs=1)
@click.argument("targets", nargs=-1)
@click.option("-o", "--output", type=str, default="result.json")
@click.option("-v", "--visualize", is_flag=True)
@click.option("-vo", "--visualize-output", type=str, default="result.html")
def compare(original, targets, output, visualize, visualize_output):
    comparison_df_list = []
    viz_dict = {}

    with click.progressbar(targets) as _targets:
        click.echo("Comparing pcap files...")
        original_pcap = Pcap(original)

        for target in _targets:
            try:
                target_pcap = Pcap(target)
            except Scapy_Exception:
                click.echo("Warning: Not a valid pcap file. Skipping...")
                continue
            comparator = Comparator(original_pcap, target_pcap, visualize)

            result_dict = comparator.get_comparisons()
            comp_dict = result_dict[list(result_dict.keys())[0]]["comparisons"]
            comparison_df_list.append(comp_dict)
            viz_dict = {**viz_dict, **result_dict}

    if comparison_df_list:
        click.echo(f"Writing results to {output}")
        with open(f"{output}.json", "w") as comp_json:
            json.dump(comparison_df_list, comp_json)
    else:
        click.echo("No results generated.")

    if visualize:
        if not viz_dict:
            click.echo("Empty List.")
        else:
            viz(viz_dict, visualize_output)


if __name__ == "__main__":
    compare()


