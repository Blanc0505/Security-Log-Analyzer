def analyze_log(file_path):
    suspicious_keywords = ["failed password", "error", "invalid user", "unathorized"]
    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            if any(keyword in line.lower() for keyword in suspicious_keywords):
                print("[WARNING] Suspicious Entry:", line.strip())