import click
from log_parser.main import analyze_authLog

@click.command()
@click.argument("logfile", type=click.Path(exists=True))
@click.option("--verbose", is_flag=True, help="more detailed output")

def main(logfile, verbose):
    print(f"Analyse von: {logfile}")
    analyze_authLog(logfile, verbose=verbose)

if __name__ == "__main__":
    main()