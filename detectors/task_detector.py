from datetime import datetime

from models.alert import create_alert


# ============================================================
# Suspicious executables
# ============================================================

SUSPICIOUS_EXECUTABLES = {
    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "rundll32.exe",
    "regsvr32.exe",
    "certutil.exe",
}


# ============================================================
# Suspicious / user-writable locations
# ============================================================

SUSPICIOUS_LOCATIONS = (
    "\\appdata\\",
    "\\temp\\",
    "\\users\\public\\",
    "\\downloads\\",
)


# ============================================================
# Trusted Windows task locations
# ============================================================

TRUSTED_TASK_PATH_PREFIX = "\\microsoft\\windows\\"


# ============================================================
# Helpers
# ============================================================

def normalize(value):

    if value is None:
        return ""

    return str(value).strip()


def is_suspicious_location(command):

    command_lower = command.lower()

    for location in SUSPICIOUS_LOCATIONS:

        if location in command_lower:
            return True

    return False


def find_suspicious_executable(command):

    command_lower = command.lower()

    for executable in SUSPICIOUS_EXECUTABLES:

        if executable in command_lower:
            return executable

    return None


def is_trusted_windows_task(task_path):

    path = normalize(task_path).lower()

    return path.startswith(
        TRUSTED_TASK_PATH_PREFIX
    )


# ============================================================
# Scheduled Task Detection
# ============================================================

def detect_scheduled_tasks(tasks):

    alerts = []

    for task in tasks:

        task_name = normalize(
            task.get("TaskName")
        )

        task_path = normalize(
            task.get("TaskPath")
        )

        command = normalize(
            task.get("Task To Run")
        )

        status = normalize(
            task.get("Status")
        )

        author = normalize(
            task.get("Author")
        )

        run_as_user = normalize(
            task.get("Run As User")
        )

        # ----------------------------------------------------
        # No command = nothing to analyze
        # ----------------------------------------------------

        if not command:
            continue

        # ----------------------------------------------------
        # Analyze task
        # ----------------------------------------------------

        suspicious_location = (
            is_suspicious_location(command)
        )

        suspicious_executable = (
            find_suspicious_executable(command)
        )

        trusted_windows_task = (
            is_trusted_windows_task(task_path)
        )

        reasons = []

        # ----------------------------------------------------
        # Suspicious location
        # ----------------------------------------------------

        if suspicious_location:

            reasons.append(
                "Task executes from a suspicious "
                "or user-writable location"
            )

        # ----------------------------------------------------
        # Suspicious executable
        #
        # Do NOT automatically flag every Windows
        # rundll32/cmd task.
        # ----------------------------------------------------

        if suspicious_executable:

            if not trusted_windows_task:

                reasons.append(
                    "Task launches suspicious executable "
                    f"{suspicious_executable}"
                )

            elif suspicious_location:

                reasons.append(
                    "Trusted Windows executable is being "
                    "launched from a suspicious location"
                )

        # ----------------------------------------------------
        # Nothing suspicious
        # ----------------------------------------------------

        if not reasons:
            continue

        # ----------------------------------------------------
        # Severity
        # ----------------------------------------------------

        if suspicious_location and suspicious_executable:

            severity = "HIGH"
            confidence = 95

        elif suspicious_location:

            severity = "HIGH"
            confidence = 90

        else:

            severity = "MEDIUM"
            confidence = 75

        # ----------------------------------------------------
        # Create alert
        # ----------------------------------------------------

        alert = create_alert(

            severity=severity,

            rule="Suspicious Scheduled Task",

            description=" | ".join(reasons),

            mitre="T1053.005",

            technique="Scheduled Task",

            confidence=confidence,

            process="Unknown",

            pid=None,

            task_name=task_name,

            task_path=task_path,

            command=command,

            status=status,

            author=author,

            run_as_user=run_as_user,

            timestamp=datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),

            recommendation=(
                "Review the scheduled task and verify "
                "that its executable and arguments "
                "are legitimate."
            )
        )

        alerts.append(alert)

    return alerts