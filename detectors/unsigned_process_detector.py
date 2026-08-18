from models.alert import create_alert

SUSPICIOUS_PATHS = [

    "\\temp\\",
    "\\users\\public\\",

]

TRUSTED_NAMES = {

    "code.exe",
    "python.exe",
    "py.exe",
    "onedrive.exe",
    "onedrive.sync.service.exe",
    "firefox.exe",
    "chrome.exe",
    "msedge.exe",
    "msedgewebview2.exe",
    "openconsole.exe",
    "discord.exe",
    "spotify.exe",
    "notion.exe",
    "epicgameslauncher.exe",
    "steam.exe",
    "docker desktop.exe",

}


def detect_unsigned_processes(processes):

    alerts = []

    for process in processes:

        exe = process.get("exe", "")

        if not exe:
            continue

        process_name = process.get(
            "name",
            ""
        ).lower()

        if process_name in TRUSTED_NAMES:
            continue

        exe_lower = exe.lower()

        if exe_lower.startswith("c:\\windows\\system32"):
            continue

        if exe_lower.startswith("c:\\windows\\syswow64"):
            continue

        suspicious = False

        for path in SUSPICIOUS_PATHS:

            if path in exe_lower:

                suspicious = True
                break

        if not suspicious:
            continue

        alerts.append(

            create_alert(

                severity="MEDIUM",

                rule="Executable Running From Suspicious Location",

                description="Process is executing from a suspicious directory.",

                mitre="T1036",

                technique="Masquerading",

                confidence=75,

                process=process.get("name"),

                pid=process.get("pid"),

                user=process.get("username"),

                path=exe,

                recommendation="Verify whether this executable is legitimate."

            )

        )

    return alerts