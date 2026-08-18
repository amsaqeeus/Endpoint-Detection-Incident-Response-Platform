from datetime import datetime


def build_timeline(alerts):
    """
    Build a chronological timeline of all detected security events.
    """

    timeline = []

    for alert in alerts:

        timeline.append({

            "timestamp": alert.get(
                "timestamp",
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ),

            "severity": alert.get(
                "severity",
                "LOW"
            ),

            "rule": alert.get(
                "rule",
                "Unknown"
            ),

            "process": alert.get(
                "process",
                "Unknown"
            ),

            "pid": alert.get(
                "pid",
                "-"
            ),

            "mitre": alert.get(
                "mitre",
                "-"
            ),

            "technique": alert.get(
                "technique",
                "-"
            ),

            "confidence": alert.get(
                "confidence",
                0
            ),

            "description": alert.get(
                "description",
                "-"
            )

        })

    # Sort events chronologically
    timeline.sort(
        key=lambda event: event["timestamp"]
    )

    return timeline