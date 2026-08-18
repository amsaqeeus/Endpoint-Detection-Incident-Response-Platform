from datetime import datetime


SUSPICIOUS_PATHS = [

    "\\temp\\",
    "\\appdata\\",
    "\\users\\public\\",
    "\\downloads\\",

]


def detect_services(services):

    alerts = []

    for service in services:

        path = service.get("binary_path", "")

        if not path:
            continue

        lower = path.lower()

        suspicious = False

        for p in SUSPICIOUS_PATHS:

            if p in lower:

                suspicious = True
                break

        if not suspicious:
            continue

        alerts.append({

            "severity": "HIGH",

            "rule": "Suspicious Windows Service",

            "description":
                "Service executable located in a user writable directory.",

            "mitre": "T1543.003",

            "technique":
                "Create or Modify System Process: Windows Service",

            "service": service.get("name"),

            "display_name": service.get("display_name"),

            "path": path,

            "state": service.get("status"),

            "confidence": 90,

            "timestamp":
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        })

    return alerts