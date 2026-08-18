from datetime import datetime


def create_alert(
    severity,
    rule,
    description,
    mitre,
    technique,
    confidence,
    process="Unknown",
    pid=None,
    **extra
):

    alert = {

        "severity": severity,

        "rule": rule,

        "description": description,

        "mitre": mitre,

        "technique": technique,

        "confidence": confidence,

        "process": process,

        "pid": pid,

        "timestamp": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    }

    alert.update(extra)

    return alert