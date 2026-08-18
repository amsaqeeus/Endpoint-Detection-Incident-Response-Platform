SEVERITY_SCORES = {

    "LOW": 20,

    "MEDIUM": 50,

    "HIGH": 80,

    "CRITICAL": 100

}


def calculate_threat_score(alerts):

    if not alerts:
        return 0

    total = 0

    for alert in alerts:

        severity = alert.get("severity", "LOW")

        total += SEVERITY_SCORES.get(
            severity,
            20
        )

    score = total / len(alerts)

    return round(score)