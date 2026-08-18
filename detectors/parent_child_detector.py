from datetime import datetime


SUSPICIOUS_PARENT_CHILD = {

    "winword.exe": [
        "powershell.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "rundll32.exe",
    ],

    "excel.exe": [
        "powershell.exe",
        "cmd.exe",
        "mshta.exe",
    ],

    "outlook.exe": [
        "powershell.exe",
        "cmd.exe",
    ],

    "chrome.exe": [
        "powershell.exe",
        "cmd.exe",
    ],

    "firefox.exe": [
        "powershell.exe",
        "cmd.exe",
    ],

    "acrord32.exe": [
        "powershell.exe",
        "cmd.exe",
    ],

}


def detect_parent_child(processes):

    alerts = []

    process_lookup = {}

    # Build PID lookup table
    for process in processes:

        process_lookup[
            process.get("pid")
        ] = process

    # Analyze relationships
    for process in processes:

        parent_pid = process.get("ppid")

        parent = process_lookup.get(parent_pid)

        if parent is None:
            continue

        parent_name = parent.get(
            "name",
            ""
        ).lower()

        child_name = process.get(
            "name",
            ""
        ).lower()

        if parent_name not in SUSPICIOUS_PARENT_CHILD:
            continue

        if child_name not in SUSPICIOUS_PARENT_CHILD[parent_name]:
            continue

        # Confidence score
        confidence = 90

        if parent_name in (
            "winword.exe",
            "excel.exe",
            "outlook.exe"
        ):
            confidence = 95

        elif parent_name in (
            "chrome.exe",
            "firefox.exe"
        ):
            confidence = 75

        alert = {

            "severity": "HIGH",

            "rule": "Suspicious Parent-Child Process",

            "description":
                f"{parent_name} spawned {child_name}",

            "mitre": "T1059",

            "technique":
                "Command and Scripting Interpreter",

            "parent_process": parent_name,

            "child_process": child_name,

            "parent_pid": parent.get("pid"),

            "child_pid": process.get("pid"),

            "command_line": process.get(
                "cmdline",
                ""
            ),

            "user": process.get(
                "username",
                "Unknown"
            ),

            "confidence": confidence,

            "recommendation":
                "Verify whether this process execution is expected. "
                "Inspect the command line, parent process, and related activities.",

            "timestamp":
                datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )

        }

        alerts.append(alert)

    return alerts