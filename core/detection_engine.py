from detectors.suspicious_process import detect_suspicious_processes
from detectors.parent_child_detector import detect_parent_child
from detectors.lolbins_detector import detect_lolbins
from detectors.unsigned_process_detector import detect_unsigned_processes
from detectors.commandline_detector import detect_commandline
from detectors.powershell_detector import detect_powershell_attacks
from detectors.persistence_detector import detect_persistence
from detectors.network_detector import detect_network_behavior
from detectors.service_detector import detect_services
from correlation.incident_builder import build_incidents
from core.threat_score import calculate_threat_score
from detectors.task_detector import detect_scheduled_tasks 

def analyze(report):

    alerts = []

    # ======================================================
    # Process-based detections
    # ======================================================

    alerts.extend(
        detect_suspicious_processes(
            report["processes"]
        )
    )

    alerts.extend(
        detect_parent_child(
            report["processes"]
        )
    )

    alerts.extend(
        detect_lolbins(
            report["processes"]
        )
    )

    alerts.extend(
        detect_unsigned_processes(
            report["processes"]
        )
    )

    alerts.extend(
        detect_commandline(
            report["processes"]
        )
    )
    alerts.extend(

          detect_services(
             report["services"]
                  )

         )

    alerts.extend(
        detect_powershell_attacks(
            report["processes"]
        )
    )

    alerts.extend(
        detect_scheduled_tasks(
            report["scheduled_tasks"]
        )
    )

    # ======================================================
    # Persistence Detection
    # ======================================================

    if report.get("persistence"):

        alerts.extend(
            detect_persistence(
                report["persistence"]
            )
        )

    # ======================================================
    # Network Detection
    # ======================================================

    if report.get("connections"):

        alerts.extend(
            detect_network_behavior(
                report["connections"]
            )
        )

    # ======================================================
    # Correlation
    # ======================================================

    incidents = build_incidents(alerts)

    # ======================================================
    # Threat Score
    # ======================================================

    threat_score = calculate_threat_score(alerts)

    # ======================================================
    # Final Report
    # ======================================================

    return {

        "alerts": alerts,

        "incidents": incidents,

        "threat_score": threat_score

    }