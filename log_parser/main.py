def analyze_log(file_path):
    with open(file_path, "r") as file:
        for line in file:
            if "failed" in line.lower():
                print("[WARNING] Suspicious Entry:", line.strip())