from collections import defaultdict


def build_incidents(alerts):

    grouped = defaultdict(list)

    for alert in alerts:

        pid = alert.get("pid")

        if pid in (None, 0):
            continue

        grouped[pid].append(alert)

    incidents = []

    incident_id = 1

    for pid, process_alerts in grouped.items():

        severity = "LOW"

        if any(a["severity"] == "HIGH" for a in process_alerts):
            severity = "HIGH"

        elif any(a["severity"] == "MEDIUM" for a in process_alerts):
            severity = "MEDIUM"

        techniques = sorted({

            alert.get("mitre")

            for alert in process_alerts

            if alert.get("mitre")

        })

        rules = sorted({

            alert.get("rule")

            for alert in process_alerts

            if alert.get("rule")

        })

        avg_confidence = round(

            sum(

                a.get("confidence", 50)

                for a in process_alerts

            )

            /

            len(process_alerts)

        )

        incidents.append({

            "id": incident_id,

            "pid": pid,

            "process": process_alerts[0].get(
                "process",
                "Unknown"
            ),

            "severity": severity,

            "alert_count": len(process_alerts),

            "confidence": avg_confidence,

            "mitre": techniques,

            "rules": rules,

            "alerts": process_alerts

        })

        incident_id += 1

    return incidents