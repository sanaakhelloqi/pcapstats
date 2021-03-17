from src.Pcap import Pcap
from src.Comparator import Comparator
from src.visualize import visualize as viz

import pickle
import json
import multiprocessing
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
    queue = multiprocessing.Queue()
    procesess = []
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
            process = multiprocessing.Process(target=compare_process, args=(queue, comparator))
            procesess.append(process)
            process.start()

        for _ in procesess:
            comparison_df_list.append(queue.get())
            viz_dict = {**viz_dict, **queue.get()}

        for process in procesess:
            process.join()

    if comparison_df_list:
        click.echo(f"Writing results to {output}")
        #stats_df = pd.concat(comparison_df_list)
        #stats_df.to_csv(output, index=False)
        #stats_df.to_json(r'{}.json'.format(output), index=False, orient='table')
        jsonString = json.dumps(comparison_df_list)
        jsonFile = open('{}.json'.format(output), "w")
        jsonFile.write(jsonString)
        jsonFile.close()
    else:
        click.echo("No results generated.")

    if visualize:
        if not viz_dict:
            click.echo("Empty List.")
        else:
            viz(viz_dict, 'visualization.html')


def compare_process(queue, comparator):
    comp_df, viz_ = comparator.get_comparisons()
    queue.put(comp_df)
    queue.put(viz_)


if __name__ == "__main__":
    compare()


