from log_parser.main import analyze_log
import sys

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: Python run.py <logfile>")
        sys.exit(1)
    analyze_log(sys.argv[1])