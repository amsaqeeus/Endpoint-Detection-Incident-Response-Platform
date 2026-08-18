from core.investigator import investigate

report = investigate()

for alert in report["alerts"]:

    print("=" * 70)
    print("Rule      :", alert.get("rule"))
    print("Severity  :", alert.get("severity"))
    print("Process   :", alert.get("process"))
    print("PID       :", alert.get("pid"))
    print("MITRE     :", alert.get("mitre"))
    print("Description:", alert.get("description"))