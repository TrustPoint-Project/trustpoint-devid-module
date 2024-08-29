import click


@click.group(help='Trustpoint DevID Module')
def cli() -> None:
    pass

# Not clear if we need this. Thus, nothing is implemented as CLI yet.