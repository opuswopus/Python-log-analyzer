import re

# Keywords we want to detect in logs
RULES = {
    "FAILED_LOGIN": r"(failed password|authentication failure|invalid user|login failed)",
    "ACCESS_DENIED": r"(access denied|permission denied|unauthorized)",
    "BLOCKED_CONNECTION": r"(blocked|denied|firewall|drop)",
    "BRUTE_FORCE": r"(too many attempts|multiple failed|brute force)",
}
# Built as a personal SOC-style log triage practice project 

def analyze_log(file_path):
    results = {rule: 0 for rule in RULES}
    matched_lines = []

    try:
        with open(file_path, "r", errors="ignore") as f:
            for line_number, line in enumerate(f, start=1):
                line_lower = line.lower()

                for rule_name, pattern in RULES.items():
                    if re.search(pattern, line_lower):
                        results[rule_name] += 1
                        matched_lines.append((rule_name, line_number, line.strip()))
    except FileNotFoundError:
        print(f"[ERROR] File not found: {file_path}")
        return

    print("\n===== LOG ANALYZER REPORT =====")
    for rule, count in results.items():
        print(f"{rule}: {count}")

    print("\n===== FLAGGED EVENTS =====")
    for rule_name, line_number, text in matched_lines[:20]:
        print(f"[{rule_name}] Line {line_number}: {text}")

    print("\n(Showing first 20 flagged lines)")
    print("================================\n")


if __name__ == "__main__":
    log_file = input("Enter the log file name (example: sample.log): ").strip()
    analyze_log(log_file)
