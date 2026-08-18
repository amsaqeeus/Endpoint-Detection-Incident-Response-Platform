from collectors.process_collector import collect_processes
from collectors.network_collector import collect_connections
from collectors.persistence_collector import collect_persistence
from collectors.service_collector import collect_services
from collectors.task_collector import collect_scheduled_tasks
from core.detection_engine import analyze
from response.response_engine import generate_recommendations 
from timeline.timeline_builder import build_timeline
from ioc.extractor import extract_iocs

def investigate():

    report = {}

    # ===========================
    # Collect Evidence
    # ===========================

    report["processes"] = collect_processes()

    report["connections"] = collect_connections()

    report["persistence"] = collect_persistence()

    report["services"] = collect_services()

    report["scheduled_tasks"] = collect_scheduled_tasks()

    # ===========================
    # Analyze
    # ===========================

    analysis = analyze(report)

    report["alerts"] = analysis["alerts"]

    report["incidents"] = analysis["incidents"]

    report["timeline"] = build_timeline(report["alerts"])

    report["iocs"] = extract_iocs(
            report["alerts"]
        )
    
    for incident in report["incidents"]:

      incident["recommendations"] = generate_recommendations(
        incident
    )

      

    report["threat_score"] = analysis["threat_score"]

    return report