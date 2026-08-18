from models.alert import create_alert

LOLBINS = {

    "powershell.exe": [

        "-enc",
        "-encodedcommand",
        "downloadstring",
        "invoke-expression",
        "iex(",

    ],

    "cmd.exe": [

        "/c",
        "powershell",
        "certutil",

    ],

    "mshta.exe": [

        "http://",
        "https://",

    ],

    "regsvr32.exe": [

        "http://",
        "https://",

    ],

    "rundll32.exe": [

        "javascript:",
        "http://",

    ],

    "certutil.exe": [

        "-urlcache",
        "-decode",
        "-encode",

    ],

}


def detect_lolbins(processes):

    alerts = []

    for process in processes:

        process_name = process.get(
            "name",
            ""
        ).lower()

        if process_name not in LOLBINS:
            continue

        command = process.get(
            "cmdline",
            ""
        ).lower()

        matched_keyword = None

        for keyword in LOLBINS[process_name]:

            if keyword in command:

                matched_keyword = keyword

                break

        if matched_keyword is None:
            continue

        confidence = 70

        if process_name == "powershell.exe":
            confidence = 95

        elif process_name == "mshta.exe":
            confidence = 95

        elif process_name == "regsvr32.exe":
            confidence = 95

        elif process_name == "certutil.exe":
            confidence = 95

        elif process_name == "rundll32.exe":
            confidence = 90

        alerts.append(

            create_alert(

                severity="HIGH",

                rule="Suspicious LOLBin Usage",

                description=f"{process_name} executed with suspicious argument '{matched_keyword}'",

                mitre="T1218",

                technique="System Binary Proxy Execution",

                confidence=confidence,

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

                matched_keyword=matched_keyword,

                recommendation="Investigate why this LOLBin was executed with suspicious arguments."

            )

        )

    return alerts