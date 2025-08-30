import re
from datetime import datetime, timedelta
from collections import defaultdict, deque

ip_events = defaultdict(lambda: deque())
already_warned = set()
summaryDict = defaultdict(lambda: {"failures": 0, "alarms": 0})

def analyze_authLog(file_path, verbose_flag=False, summary_flag=False, window=timedelta(seconds=60), threshold=5):
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
                if verbose_flag:
                    print("[!] Regex warning:", label, "|", line.strip())

                if pat in (rx_failed, rx_invalid):
                    if timestamp is not None and ips:
                        for ip_str in ips:
                            summaryDict[ip_str]["failures"] += 1
                            #print("ip/timestamp:", ip_str, timestamp)  DEBUG 
                            events = ip_events[ip_str]
                            events.append(timestamp)

                            while events and (timestamp - events[0]) > window:
                                events.popleft()
                            
                            if len(events) >= threshold and ip_str not in already_warned:
                                summaryDict[ip_str]["alarms"] += 1
                                print(f"[!!!] Brute-Force-Attack warning: IP {ip_str} crossed the threshold ({threshold}) for failed attempts in {window}")
                                already_warned.add(ip_str)
                            elif len(events) < threshold and ip_str in already_warned:
                                #print("ip/count:", ip_str, len(events)) DEBUG
                                already_warned.remove(ip_str)
                break
            if summary_flag:
                for ip, stats in summaryDict.items():
                    print(f"IP: {ip} --> Failures: {stats['failures']} | Alarms: {stats['alarms']}")

