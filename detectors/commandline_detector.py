from models.alert import create_alert


SUSPICIOUS_PATTERNS = {

    "powershell.exe": [
        "-enc",
        "-encodedcommand",
        "-executionpolicy bypass",
        "-nop",
        "-w hidden",
        "iex(",
        "invoke-expression",
        "downloadstring",
        "downloadfile",
    ],

    "cmd.exe": [
        "certutil",
        "bitsadmin",
        "powershell",
    ],

    "mshta.exe": [
        "http://",
        "https://",
    ],

    "rundll32.exe": [
        "javascript:",
    ],

    "regsvr32.exe": [
        "http://",
        "https://",
    ],

}


def detect_commandline(processes):

    alerts = []

    for process in processes:

        process_name = process.get(
            "name",
            ""
        ).lower()

        command = process.get(
            "cmdline",
            ""
        ).lower()

        if process_name not in SUSPICIOUS_PATTERNS:
            continue

        for pattern in SUSPICIOUS_PATTERNS[process_name]:

            if pattern in command:

                alerts.append(

                    create_alert(

                        severity="HIGH",

                        rule="Suspicious Command Line",

                        description=f"Suspicious pattern '{pattern}' detected.",

                        mitre="T1059",

                        technique="Command and Scripting Interpreter",

                        confidence=90,

                        process=process.get("name"),

                        pid=process.get("pid"),

                        user=process.get(
                            "username",
                            "Unknown"
                        ),

                        command_line=process.get(
                            "cmdline",
                            ""
                        ),

                        matched_keyword=pattern,

                        recommendation="Review the command line and verify whether the execution is legitimate."

                    )

                )

    return alerts