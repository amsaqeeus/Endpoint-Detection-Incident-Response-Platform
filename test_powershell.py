from collectors.process_collector import collect_processes
from detectors.powershell_detector import detect_powershell_attacks


def main():

    processes = collect_processes()

    alerts = detect_powershell_attacks(processes)

    print("=" * 80)
    print("SentinelIR - PowerShell Detector")
    print("=" * 80)

    print(f"\nAlerts: {len(alerts)}\n")

    for alert in alerts:

        print("-" * 80)

        print("Rule:", alert["rule"])
        print("Keyword:", alert["matched_keyword"])
        print("PID:", alert["pid"])
        print("User:", alert["user"])
        print("Command:", alert["command_line"])

    print("\nDone.")


if __name__ == "__main__":
    main()