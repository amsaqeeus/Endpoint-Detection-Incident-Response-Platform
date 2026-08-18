from datetime import datetime
import os


KNOWN_PROGRAMS = [

    "onedrive",

    "securityhealth",

    "epicgames",

    "docker",

    "teams",

    "adobe",

    "google",

    "edge",

    "notion",

    "spotify",

    "discord",

    "steam",

]


def detect_persistence(data):

    alerts = []


    # -------------------------
    # Registry Run Keys
    # -------------------------

    for entry in data["registry"]:

        value = entry["value"].lower()

        trusted = False

        for app in KNOWN_PROGRAMS:

            if app in value:

                trusted = True
                break

        if trusted:
            continue


        alerts.append({

            "severity": "HIGH",

            "rule": "Suspicious Registry Persistence",

            "description":
                "Unknown application configured to start automatically.",

            "mitre": "T1547.001",

            "technique":
                "Registry Run Keys",

            "name": entry["name"],

            "path": entry["value"],

            "confidence": 90,

            "timestamp":
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        })


    # -------------------------
    # Startup Folder
    # -------------------------

    for entry in data["startup"]:

        filename = entry["name"].lower()

        if filename == "desktop.ini":
            continue

        if filename.endswith(".lnk"):

            trusted = False

            for app in KNOWN_PROGRAMS:

                if app in filename:

                    trusted = True
                    break

            if trusted:
                continue


        alerts.append({

            "severity": "MEDIUM",

            "rule": "Startup Folder Persistence",

            "description":
                "Unknown file located in Startup folder.",

            "mitre": "T1547.001",

            "technique":
                "Startup Folder",

            "name": entry["name"],

            "path": entry["value"],

            "confidence": 80,

            "timestamp":
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        })

    return alerts