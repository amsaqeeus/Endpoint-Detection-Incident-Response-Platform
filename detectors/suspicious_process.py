from models.alert import create_alert


# ==========================================================
# Suspicious Writable Locations
# ==========================================================

SUSPICIOUS_PATHS = [

    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\",
    "\\downloads\\",
    "\\users\\public\\",
]


# ==========================================================
# Windows System Locations
# ==========================================================

SYSTEM_PATHS = [

    "c:\\windows\\system32\\",
    "c:\\windows\\syswow64\\",
    "c:\\windows\\",
]


# ==========================================================
# Trusted Applications
# ==========================================================

TRUSTED_PROCESSES = {

    "code.exe",
    "python.exe",
    "py.exe",

    "onedrive.exe",
    "onedrive.sync.service.exe",

    "openconsole.exe",

    "firefox.exe",
    "chrome.exe",
    "msedge.exe",
    "msedgewebview2.exe",

    "explorer.exe",
    "taskmgr.exe",

    "notion.exe",
    "discord.exe",
    "spotify.exe",
    "steam.exe",
    "epicgameslauncher.exe",

    "docker desktop.exe",
}


# ==========================================================
# Detection
# ==========================================================

def detect_suspicious_processes(processes):

    alerts = []

    for process in processes:

        exe = process.get("exe", "")

        if not exe:
            continue

        exe_lower = exe.lower()

        process_name = process.get(
            "name",
            "Unknown"
        )

        process_name_lower = process_name.lower()

        # --------------------------------------------------
        # Ignore Windows system binaries
        # --------------------------------------------------

        if any(
            exe_lower.startswith(path)
            for path in SYSTEM_PATHS
        ):
            continue

        # --------------------------------------------------
        # Ignore trusted applications
        # --------------------------------------------------

        if process_name_lower in TRUSTED_PROCESSES:
            continue

        # --------------------------------------------------
        # Check suspicious location
        # --------------------------------------------------

        matched_path = None

        for suspicious_path in SUSPICIOUS_PATHS:

            if suspicious_path in exe_lower:

                matched_path = suspicious_path

                break

        if not matched_path:
            continue

        # --------------------------------------------------
        # Determine severity
        # --------------------------------------------------

        severity = "HIGH"
        confidence = 85

        # Executables from Temp are particularly interesting
        if "\\temp\\" in exe_lower:

            severity = "HIGH"
            confidence = 85

        # Downloads are suspicious but not automatically malicious
        elif "\\downloads\\" in exe_lower:

            severity = "MEDIUM"
            confidence = 75

        # AppData is commonly used by legitimate software,
        # so confidence is slightly lower.
        elif "\\appdata\\" in exe_lower:

            severity = "MEDIUM"
            confidence = 70

        # Public directory is highly unusual for executables
        elif "\\users\\public\\" in exe_lower:

            severity = "HIGH"
            confidence = 85

        # --------------------------------------------------
        # Create Alert
        # --------------------------------------------------

        alerts.append(

            create_alert(

                severity=severity,

                rule="Executable Running From Suspicious Location",

                description=(
                    "Process is executing from a "
                    "user-writable directory."
                ),

                mitre="T1036",

                technique="Masquerading",

                confidence=confidence,

                process=process_name,

                pid=process.get("pid"),

                user=process.get(
                    "username",
                    "Unknown"
                ),

                path=exe,

                recommendation=(
                    "Verify the executable's origin, "
                    "digital signature, parent process, "
                    "and file reputation."
                )

            )

        )

    return alerts