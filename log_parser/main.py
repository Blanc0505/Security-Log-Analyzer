import re
import ipaddress
from datetime import datetime, timedelta
from collections import defaultdict, deque
from typing import TypedDict

class SummaryEntry:
    def __init__(self) -> None:
        self.failures:      int = 0
        self.alarms:        int = 0
        self.flagged:       bool = False
        self.first_seen:    datetime | None = None
        self.last_seen:     datetime | None = None

    def increment_failures(self, ts: datetime | None = None) -> None:
        self.failures += 1
        if ts:
            if not self.first_seen:
                self.first_seen = ts
            self.last_seen = ts

    def increment_alarm(self) -> None:
        self.alarms += 1
        self.flagged = True

def normalize_ip_lenient(s: str | None) -> str | None:
    if not s: return None
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return None
    if ip.is_loopback or ip.is_multicast:
        return None
    return ip.exploded

def prune_deque(dq, now, window ):
    while dq:
        head = dq[0]
        ts = head[0] if isinstance(head, tuple) else head
        if (now - ts) > window:
            dq.popleft()
        else:
            break

#for analyze_auth_log
ip_events = defaultdict(lambda: deque())
already_warned = set()
summary_auth: defaultdict[str, SummaryEntry] = defaultdict(SummaryEntry)

#for analyze_firewall_log
summary_fw: defaultdict[str, SummaryEntry] = defaultdict(SummaryEntry)
ports_by_src_dst    = defaultdict(deque)    # (src,dst) -> deque[(ts, dpt)]
dsts_by_src_port    = defaultdict(deque)    # (src,dpt) -> deque[(ts, dst)]
syn_by_flow         = defaultdict(deque)    # (src,dst) -> deque[ts]    
warned_vertical     = set()                 # {(src,dst)}
warned_horizontal   = set()                 # {(src,dst)}   
warned_syn          = set()                 # {(src,dst)}

def analyze_auth_log(file_path, verbose_flag=False, summary_flag_auth=False, window=timedelta(seconds=60), threshold=5):
    patterns_auth = [
        re.compile(r"\bfailed password\b", re.IGNORECASE),
        re.compile(r"\binvalid user\b", re.IGNORECASE),
        re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", re.IGNORECASE),
        re.compile(r"\baccepted password\b", re.IGNORECASE),
    ] 
    
    rx_failed = patterns_auth[0]
    rx_invalid = patterns_auth[1]
    rx_ip = patterns_auth[2]
    rx_success = patterns_auth[3]
    
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

            for pat in patterns_auth:
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
                            summary_auth[ip_str].increment_failures(timestamp)
                            #print("ip/timestamp:", ip_str, timestamp)  DEBUG 
                            events = ip_events[ip_str]
                            events.append(timestamp)

                            while events and (timestamp - events[0]) > window:
                                events.popleft()
                            
                            if len(events) >= threshold and ip_str not in already_warned:
                                summary_auth[ip_str].increment_alarm()
                                print(f"[!!!] Brute-Force-Attack warning: IP {ip_str} crossed the threshold ({threshold}) for failed attempts in time-window: {window}")
                                already_warned.add(ip_str)
                            elif len(events) < threshold and ip_str in already_warned:
                                #print("ip/count:", ip_str, len(events)) DEBUG
                                already_warned.remove(ip_str)
                break
        if summary_flag_auth:
            for ip, stats in summary_auth.items():
                print(f"IP: {ip} --> Failures: {stats.failures} | Alarms: {stats.alarms} | Flagged: {stats.flagged}")

def analyze_firewall_log(file_path, verbose_flag=False, summary_flag_fw=False, window=timedelta(seconds=60), vert_ports=5, horz_hosts=5, syn_burst=10):

    IPV4 = r"\d{1,3}(?:\.\d{1,3}){3}" 
    rx_ts           = re.compile(r"^(?P<mon>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})")
    rx_action       = re.compile(r"\[(?:UFW|IPT|IPTables)\s+(?P<action>ALLOW|BLOCK|REJECT|DROP)\]", re.I)

    rx_src          = re.compile(rf"\bSRC=(?P<src>{IPV4})\b")
    rx_dst          = re.compile(rf"\bDST=(?P<dst>{IPV4})\b")
    rx_proto        = re.compile(rf"\bPROTO=(?P<proto>TCP|UDP|ICMP)\b", re.I)
    rx_dpt          = re.compile(r"\bDPT=(?P<dpt>\d+)\b")

    rx_syn          = re.compile(r'\bSYN\b')
    rx_ack          = re.compile(r'\bACK\b')

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            timestamp = None

            src_m = rx_src.search(line)
            dst_m = rx_dst.search(line)
            src = src_m.group("src") if src_m else None
            dst = dst_m.group("dst") if dst_m else None

            proto_m = rx_proto.search(line)
            proto = proto_m.group("proto").upper() if proto_m else None

            dpt_m = rx_dpt.search(line)
            dpt = int(dpt_m.group("dpt")) if dpt_m else None

            act_m = rx_action.search(line)
            act = act_m.group("action").upper() if act_m else None

            is_syn = bool(rx_syn.search(line))
            is_ack = bool(rx_ack.search(line))

            m = rx_ts.search(line)
            if not m:
                continue
            month_str = m.group("mon").title()
            day_str = m.group("day")
            time_str = m.group("time")
            year = datetime.now().year
            dt_str = f"{day_str} {month_str} {year} {time_str}"
            timestamp = datetime.strptime(dt_str, "%d %b %Y %H:%M:%S")
            
            """
            if verbose_flag:                                                                                                # Debug
                print("DBG", timestamp, src, dst, proto, dpt, act, "SYN" if is_syn else "-", "ACK" if is_ack else "-")
            """

            raw_src = src
            src = normalize_ip_lenient(src)

            """
            if verbose_flag:
                print("DBG-pre", timestamp, "raw_src=", raw_src, "norm_src=", src,
                    "dst=", dst, "proto=", proto, "dpt=", dpt, "act=", act,
                    "flags=", ("SYN" if is_syn else "-"), ("ACK" if is_ack else "-"))
            """

            if not src:
                # if verbose_flag: print("DBG-skip: no valid src")
                continue
            
            key_v = (src, dst)
            key_h = (src, dpt)
            """
            if verbose_flag:
                print("DBG-keys", key_v, key_h)
            """

            if dpt is not None:                                     # vertical
                dq = ports_by_src_dst[key_v]    
                dq.append((timestamp, dpt))
                prune_deque(dq, timestamp, window)

                unique_ports = {p for (_, p) in dq if p is not None}
                if verbose_flag:
                    print("DBG-vert", key_v, len(unique_ports))
                if len(unique_ports) >= vert_ports and key_v not in warned_vertical:
                    print(f"[!!!] Port-Scan (vertical): SRC {src} --> DST {dst} touched {len(unique_ports)} unique ports in window {window}")
                    summary_fw[src].increment_alarm()
                    warned_vertical.add(key_v)

            if dpt is not None and dst is not None:                 # horizontal
                dq = dsts_by_src_port[key_h]
                dq.append((timestamp, dst))
                prune_deque(dq,timestamp, window)

                unique_dsts = {d for (_, d) in dq if d is not None}
                if len(unique_dsts) >= horz_hosts and key_h not in warned_horizontal:
                    print(f"[!!!] Port-Scan (horizontal): SRC {src} probed port {dpt} on {len(unique_dsts)} hosts in window {window}")
                    summary_fw[src].increment_alarm()
                    warned_horizontal.add(key_h)

            if proto == "TCP" and is_syn and not is_ack:            # SYN-flood
                dq = syn_by_flow[key_v]
                dq.append(timestamp)
                prune_deque(dq, timestamp, window)

                if len(dq) >= syn_burst and key_v not in warned_syn:
                    print(f"[!!!] SYN-burst: SRC {src} --> DST {dst} count={len(dq)} in window {window}")
                    summary_fw[src].increment_alarm()
                    warned_syn.add(key_v)
            
            if act in {"BLOCK", "DROP", "REJECT"}:
                summary_fw[src].increment_failures(timestamp)

        if summary_flag_fw:
            for ip, stats in summary_fw.items():
                print(f"IP: {ip} --> Failures: {stats.failures} | Alarms: {stats.alarms} | Flagged: {stats.flagged}")
