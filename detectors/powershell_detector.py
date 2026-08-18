from datetime import datetime
from models.alert import create_alert

SUSPICIOUS_KEYWORDS = [

    "-enc",
    "-encodedcommand",

    "invoke-expression",
    "iex",

    "downloadstring",

    "invoke-webrequest",

    "new-object net.webclient",

    "frombase64string",

    "executionpolicy bypass",

    "-nop",

    "-w hidden",
    "-windowstyle hidden",

]


def detect_powershell_attacks(processes):

    alerts = []

    for process in processes:

        name = process.get(
            "name",
            ""
        ).lower()

        if name != "powershell.exe":
            continue

        cmdline = process.get(
            "cmdline",
            ""
        ).lower()

        for keyword in SUSPICIOUS_KEYWORDS:

            if keyword in cmdline:
              alerts.append(

                   create_alert(

                         severity="HIGH",

                            rule="Suspicious PowerShell Command",

                           description=f"PowerShell contains '{keyword}'",

                           mitre="T1059.001",

                           technique="PowerShell",

                           confidence=95,

                           process=name,

                           pid=process.get("pid"),

                           user=process.get("username", "Unknown"),

                           command_line=process.get("cmdline", ""),

                           matched_keyword=keyword,

                           recommendation="Review this PowerShell command immediately."

    )

)

    return alerts