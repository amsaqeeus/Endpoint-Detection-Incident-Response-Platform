import ipaddress

from models.alert import create_alert


# ============================================================
# Processes that deserve stronger network scrutiny
# ============================================================

SUSPICIOUS_PROCESSES = {

    "powershell.exe",
    "cmd.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "certutil.exe",
    "bitsadmin.exe",
}


# ============================================================
# Ports commonly associated with suspicious / C2 activity
# ============================================================

SUSPICIOUS_PORTS = {

    4444,
    5555,
    1337,
    9001,
    8081,

}


# ============================================================
# Common legitimate application processes
# ============================================================

TRUSTED_NETWORK_PROCESSES = {

    "chrome.exe",
    "firefox.exe",
    "msedge.exe",
    "msedgewebview2.exe",
    "code.exe",
    "onedrive.exe",
    "onedrive.sync.service.exe",
    "spotify.exe",
    "discord.exe",
    "steam.exe",
    "epicgameslauncher.exe",
    "svchost.exe",
    "explorer.exe",
    "system.exe",
}


# ============================================================
# IP validation
# ============================================================

def is_public_ip(ip):

    if not ip:
        return False

    try:

        address = ipaddress.ip_address(ip)

        return (
            not address.is_private
            and not address.is_loopback
            and not address.is_link_local
            and not address.is_multicast
            and not address.is_reserved
        )

    except Exception:

        return False


# ============================================================
# Network Detection
# ============================================================

def detect_network_behavior(connections):

    alerts = []

    for conn in connections:

        remote_ip = conn.get("remote_ip")

        remote_port = conn.get("remote_port")

        process_name = conn.get(
            "process",
            "Unknown"
        )

        process = process_name.lower()

        # ----------------------------------------------------
        # Ignore connections without a remote endpoint
        # ----------------------------------------------------

        if not remote_ip:
            continue

        # ----------------------------------------------------
        # Ignore private/local addresses
        # ----------------------------------------------------

        if not is_public_ip(remote_ip):
            continue

        severity = None

        confidence = 0

        reasons = []

        # ====================================================
        # CASE 1 — Suspicious process communicating externally
        # ====================================================

        if process in SUSPICIOUS_PROCESSES:

            severity = "HIGH"

            confidence = 90

            reasons.append(
                f"Suspicious process {process_name} "
                f"connected to external IP"
            )

        # ====================================================
        # CASE 2 — Suspicious destination port
        # ====================================================

        if remote_port in SUSPICIOUS_PORTS:

            severity = "HIGH"

            confidence = max(
                confidence,
                95
            )

            reasons.append(
                f"Connection to suspicious port "
                f"{remote_port}"
            )

        # ====================================================
        # CASE 3 — Unknown process + suspicious port
        # ====================================================

        if (
            process == "unknown"
            and remote_port in SUSPICIOUS_PORTS
        ):

            severity = "HIGH"

            confidence = 95

            reasons.append(
                "Unknown process communicating "
                "through a suspicious port"
            )

        # ====================================================
        # Ignore ordinary browser/application traffic
        # ====================================================

        if process in TRUSTED_NETWORK_PROCESSES:

            if remote_port not in SUSPICIOUS_PORTS:

                continue

        # ====================================================
        # Unknown process with normal port
        # ====================================================

        if not reasons:

            severity = "LOW"

            confidence = 35

            reasons.append(
                "Unknown process established "
                "an external network connection"
            )

        # ====================================================
        # Create alert
        # ====================================================

        alerts.append(

            create_alert(

                severity=severity,

                rule="Suspicious Network Connection",

                description=" | ".join(reasons),

                mitre="T1071",

                technique="Application Layer Protocol",

                confidence=confidence,

                process=conn.get(
                    "process"
                ),

                pid=conn.get(
                    "pid"
                ),

                remote_ip=remote_ip,

                remote_port=remote_port,

                local_ip=conn.get(
                    "local_ip"
                ),

                local_port=conn.get(
                    "local_port"
                ),

                status=conn.get(
                    "status"
                ),

                recommendation=(
                    "Investigate the remote endpoint, "
                    "process ownership, destination port, "
                    "and whether the connection is expected."
                )

            )

        )

    return alerts