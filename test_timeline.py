from core.investigator import investigate

report = investigate()

print("=" * 80)
print("ATTACK TIMELINE")
print("=" * 80)

for event in report["timeline"]:

    print()

    print(event["time"])

    print("Process :", event["process"])

    print("Rule    :", event["rule"])

    print("Severity:", event["severity"])

    print("Desc    :", event["description"])

    print("-" * 60)