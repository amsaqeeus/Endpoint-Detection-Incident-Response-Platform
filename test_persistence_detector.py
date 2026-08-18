from collectors.persistence_collector import collect_persistence
from detectors.persistence_detector import detect_persistence


def main():

    data = collect_persistence()

    alerts = detect_persistence(data)

    print("=" * 80)
    print("SentinelIR - Persistence Detector")
    print("=" * 80)

    print(f"\nAlerts Found: {len(alerts)}\n")

    for alert in alerts:

        print("-" * 80)

        print("Rule       :", alert["rule"])
        print("Severity   :", alert["severity"])
        print("MITRE      :", alert["mitre"])
        print("Name       :", alert["name"])
        print("Path       :", alert["path"])

    print("\nFinished")


if __name__ == "__main__":
    main()