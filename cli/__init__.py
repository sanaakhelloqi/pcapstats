import click

from cli.compare import cli_compare
from cli.stats import cli_stats
from cli.filter import cli_filter


@click.group()
@click.version_option()
def cli(**kwargs):
    pass


cli.add_command(cli_compare)
cli.add_command(cli_stats)
cli.add_command(cli_filter)
