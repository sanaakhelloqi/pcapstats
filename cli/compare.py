from concurrent.futures._base import Future
from typing import Any

from src.Pcap import Pcap
from src.Comparator import Comparator
import src.utils as utils

import multiprocessing
import click
from scapy.error import Scapy_Exception
import pandas as pd


@click.command()
@click.argument("original", nargs=1)
@click.argument("targets", nargs=-1)
@click.option("-o", "--output", type=str, default="result.csv")
@click.option("-v", "--visualize", is_flag=True)
@click.option("-vo", "--visualize-output", type=str, default="result.pdf")
def compare(original, targets, output, visualize, visualize_output):
    comparison_df_list = []
    pdf_output = []
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
            pdf_output.append(queue.get())

        for process in procesess:
            process.join()


    if comparison_df_list:
        click.echo(f"Writing results to {output}")
        stats_df = pd.concat(comparison_df_list)
        stats_df.to_csv(output, index=False)
    else:
        click.echo("No results generated.")

    if visualize:
        if not pdf_output:
            click.echo("Empty List.")
        else:
            utils.merge_pdfs(pdf_output, delete_originals=True, out=visualize_output)


def compare_process(queue, comparator):
    comp_df, pdfs = comparator.get_comparisons()
    queue.put(comp_df)
    queue.put(pdfs)



if __name__ == "__main__":
    compare()


