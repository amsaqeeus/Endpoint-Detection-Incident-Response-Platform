def generate_recommendations(incident):

    recommendations = []

    techniques = incident.get("mitre", [])

    # PowerShell
    if "T1059.001" in techniques:

        recommendations.append(
            "Terminate the PowerShell process."
        )

        recommendations.append(
            "Review the executed PowerShell command."
        )

    # Network Connection
    if "T1071" in techniques:

        recommendations.append(
            "Block the remote IP address."
        )

        recommendations.append(
            "Review firewall logs."
        )

    # Registry Persistence
    if "T1547.001" in techniques:

        recommendations.append(
            "Remove malicious registry Run Keys."
        )

    # Scheduled Tasks
    if "T1053.005" in techniques:

        recommendations.append(
            "Delete suspicious scheduled tasks."
        )

    # Windows Service
    if "T1543.003" in techniques:

        recommendations.append(
            "Disable suspicious Windows services."
        )

    # LOLBins
    if "T1218" in techniques:

        recommendations.append(
            "Investigate LOLBin execution."
        )

    if incident["severity"] == "HIGH":

        recommendations.append(
            "Isolate the affected host."
        )

        recommendations.append(
            "Collect a memory dump."
        )

    return list(set(recommendations))