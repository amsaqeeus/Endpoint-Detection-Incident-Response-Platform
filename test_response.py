from core.investigator import investigate


report = investigate()

print("=" * 80)
print("SentinelIR Response Engine")
print("=" * 80)

for incident in report["incidents"]:

    print()

    print(f"Incident #{incident['id']}")

    print("Severity:", incident["severity"])

    print()

    print("Recommendations")

    for rec in incident["recommendations"]:

        print(" -", rec)

    print("-" * 80)