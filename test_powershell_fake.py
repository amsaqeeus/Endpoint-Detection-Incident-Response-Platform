from detectors.powershell_detector import detect_powershell_attacks


fake_processes = [

    {

        "name": "powershell.exe",

        "pid": 9999,

        "username": "TEST",

        "cmdline":
        "powershell.exe -EncodedCommand SQBmACgAdABlAHMAdAAp"

    }

]


alerts = detect_powershell_attacks(fake_processes)


print("=" * 60)

print("PowerShell Detector Test")

print("=" * 60)

print()

print(f"Alerts Found: {len(alerts)}")

print()

for alert in alerts:

    print(alert)