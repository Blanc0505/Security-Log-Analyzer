import re

def analyze_authLog(file_path):
    patterns = [
        re.compile(r"\bfailed password\b", re.IGNORECASE),
        re.compile(r"\binvalid user\b", re.IGNORECASE),
        re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", re.IGNORECASE),
        re.compile(r"[A-z][a-z]{2} \\d{1,2} \\d{2}:\\d{2}:\\d{2}", re.IGNORECASE)
    ] 

    labels = {
        r"\b\d{1,3}(?:\.\d{1,3}){3}\b":                     "IP-Pattern",
        r"\bfailed password\b":                             "Login-Failure",
        r"\binvalid user\b":                                "Invalid-User",
        r"[A-z][a-z]{2} \\d{1,2} \\d{2}:\\d{2}:\\d{2}":     "Date"
    }

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            for pat in patterns:
                if pat.search(line):
                    print("[!] Regex warning:", labels[pat.pattern], "|", line.strip())
                    break
