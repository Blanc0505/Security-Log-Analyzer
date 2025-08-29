import re
from datetime import datetime, timedelta
from collections import defaultdict, deque

ip_events = defaultdict(lambda: deque())
WINDOW = timedelta(seconds=10)
THRESHOLD = 3

def analyze_authLog(file_path, verbose=False):
    patterns = [
        re.compile(r"\bfailed password\b", re.IGNORECASE),
        re.compile(r"\binvalid user\b", re.IGNORECASE),
        re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", re.IGNORECASE),
        re.compile(r"\baccepted password\b", re.IGNORECASE),
    ] 

    rx_failed = patterns[0]
    rx_invalid = patterns[1]
    rx_ip = patterns[2]
    rx_success = patterns[3]

    timestamp_pattern = re.compile(
        r"(?P<month>[A-Za-z]{3})\s+"
        r"(?P<day>\d{1,2})\s+"
        r"(?P<time>\d{2}:\d{2}:\d{2})",
        re.IGNORECASE
    )

    labels = {
        rx_failed:      "Login-Failure",
        rx_invalid:     "Invalid-User",
        rx_ip:          "IP-Pattern",
        rx_success:     "Login-Success",
    }

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            timestamp = None
            m = timestamp_pattern.search(line)
            if m:
                month_str = m.group("month").title()
                day_str = m.group("day")
                time_str = m.group("time")
                year = datetime.now().year
                dt_str = f"{day_str} {month_str} {year} {time_str}"
                timestamp = datetime.strptime(dt_str, "%d %b %Y %H:%M:%S")
            
            ips = rx_ip.findall(line)

            for pat in patterns:
                if not pat.search(line):
                    continue
                if pat in (rx_success, rx_ip):
                    continue
                label = labels.get(pat, pat.pattern)
                if verbose:
                    print("[!] Regex warning:", label, "|", line.strip())

                if pat in (rx_failed, rx_invalid):
                    if timestamp is not None and ips:
                        for ip_str in ips:
                            #print("DBG ip/timestamp:", ip_str, timestamp)  DEBUG 
                            events = ip_events[ip_str]
                            events.append(timestamp)

                            while events and (timestamp - events[0]) > WINDOW:
                                events.popleft()
                            
                            if len(events) > THRESHOLD:
                                print(f"[!] Brute-Force-Attack warning: IP {ip_str} has {len(events)} failed attempts in {WINDOW}")
                break
