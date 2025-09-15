import click
from datetime import timedelta
from log_parser.main import analyze_auth_log
from log_parser.main import analyze_firewall_log

@click.command()
@click.argument("logfile", type=click.Path(exists=True))
@click.option("--verbose", is_flag=True, help="more detailed output")
@click.option("--window", type=click.IntRange(min=1), default=60, show_default=True, help="Window range in seconds")
@click.option("--threshold", type=click.IntRange(min=1), default=5, show_default=True, help="threshold for warning")
@click.option("--summary", is_flag=True, help="Number of failures and alarms per IP")
@click.option("--vert-ports", type=click.IntRange(min=5), default=5, show_default=True, help="threshold for different ports")
@click.option("--horz-hosts", type=click.IntRange(min=5), default=5, show_default=True, help="threshold for different dst")
@click.option("--syn-burst", type=click.IntRange(min=10), default=10, show_default=True, help="threshold for SYN packet count")

#VERTICAL_PORTS_THRESHOLD   = 20; HORIZONTAL_HOSTS_THRESHOLD = 20; SYN_BURST_THRESHOLD = 50

def main(logfile, verbose, summary, window, threshold, vert_ports, horz_hosts, syn_burst):
    print(f"Analyse von: {logfile}")
    analyze_firewall_log(logfile, verbose_flag=verbose, summary_flag_fw=summary, window=timedelta(seconds=window),vert_ports=vert_ports, horz_hosts=horz_hosts, syn_burst=syn_burst)
    analyze_auth_log(logfile, verbose_flag=verbose, summary_flag_auth=summary, window=timedelta(seconds=window), threshold=threshold)

if __name__ == "__main__":
    main()