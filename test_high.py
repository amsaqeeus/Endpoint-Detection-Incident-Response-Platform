from core.investigator import investigate

report = investigate()

for alert in report["alerts"]:

    if alert["severity"] == "HIGH":

        print("=" * 70)

        print("Rule:", alert.get("rule"))

        print("Process:", alert.get("process"))

        print("PID:", alert.get("pid"))

        print("Description:", alert.get("description"))

        print("Confidence:", alert.get("confidence"))

        print("MITRE:", alert.get("mitre"))