import re


PRIVATE_IP_RANGES = (
    "10.",
    "192.168.",
    "127.",
    "169.254.",
)


def is_valid_ip(ip):

    try:

        parts = ip.split(".")

        if len(parts) != 4:
            return False

        return all(
            0 <= int(part) <= 255
            for part in parts
        )

    except ValueError:

        return False


def is_private_ip(ip):

    return ip.startswith(PRIVATE_IP_RANGES)


def extract_iocs(alerts):

    iocs = {

        "ips": set(),

        "urls": set(),

        "paths": set(),

        "commands": set(),

        "registry": set(),

    }


    for alert in alerts:

        # ==================================================
        # NETWORK
        # ==================================================

        remote_ip = alert.get("remote_ip")

        if remote_ip:

            if (
                is_valid_ip(remote_ip)
                and not is_private_ip(remote_ip)
            ):

                iocs["ips"].add(remote_ip)


        # ==================================================
        # URLS
        # ==================================================

        text_fields = [

            alert.get("command_line", ""),

            alert.get("command", ""),

            alert.get("description", ""),

            alert.get("path", ""),

        ]


        for text in text_fields:

            if not text:
                continue

            urls = re.findall(
                r"https?://[^\s\"']+",
                text
            )

            for url in urls:

                iocs["urls"].add(url)


        # ==================================================
        # SUSPICIOUS EXECUTABLE PATH
        # ==================================================

        path = alert.get("path")

        if path:

            iocs["paths"].add(path)


        # ==================================================
        # COMMAND LINE
        # ==================================================

        command_line = alert.get("command_line")

        if command_line:

            iocs["commands"].add(
                command_line
            )


        command = alert.get("command")

        if command:

            iocs["commands"].add(
                command
            )


        # ==================================================
        # REGISTRY
        # ==================================================

        rule = alert.get(
            "rule",
            ""
        )


        if (
            "registry" in rule.lower()
            or "run key" in str(
                alert.get("technique", "")
            ).lower()
        ):

            registry_path = alert.get("path")

            if registry_path:

                iocs["registry"].add(
                    registry_path
                )

            else:

                name = alert.get("name")

                if name:

                    iocs["registry"].add(
                        name
                    )


    # ======================================================
    # Convert sets → sorted lists
    # ======================================================

    for key in iocs:

        iocs[key] = sorted(
            iocs[key]
        )


    return iocs