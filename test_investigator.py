from core.investigator import investigate


def main():

    report = investigate()

    print("=" * 80)
    print("SentinelIR Investigation")
    print("=" * 80)

    print()

    print("Processes     :", len(report["processes"]))
    print("Connections   :", len(report["connections"]))
    print("Persistence   :", len(report["persistence"]["registry"]))
    print("Services      :", len(report["services"]))

    print()

    print("Alerts        :", len(report["alerts"]))
    print("Incidents     :", len(report["incidents"]))

    print()

    print("Threat Score")

    print(report["threat_score"])

    print()

    print("=" * 80)


if __name__ == "__main__":
    main()