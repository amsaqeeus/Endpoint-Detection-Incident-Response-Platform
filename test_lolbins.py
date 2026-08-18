from collectors.process_collector import collect_processes
from detectors.lolbins_detector import detect_lolbins


def main():

    processes = collect_processes()

    alerts = detect_lolbins(processes)

    print("=" * 80)
    print("SentinelIR - LOLBins Detector")
    print("=" * 80)

    print(f"\nDetected: {len(alerts)} LOLBins\n")

    for alert in alerts:

        print("-" * 80)

        print(f"Process     : {alert['process']}")
        print(f"PID         : {alert['pid']}")
        print(f"Severity    : {alert['severity']}")
        print(f"Confidence  : {alert['confidence']}%")
        print(f"MITRE       : {alert['mitre']}")
        print(f"Technique   : {alert['technique']}")
        print(f"User        : {alert['user']}")
        print(f"Command     : {alert['command_line']}")

    print("\n" + "=" * 80)
    print("Finished")
    print("=" * 80)


if __name__ == "__main__":
    main()