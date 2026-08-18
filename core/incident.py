from collectors.process_collector import collect_processes
from collectors.network_collector import collect_connections
from collectors.service_collector import collect_services
from collectors.startup_collector import collect_startup

from core.detection_engine import analyze


def investigate():

    report = {}

    report["processes"] = collect_processes()

    report["connections"] = collect_connections()

    report["services"] = collect_services()

    report["startup"] = collect_startup()

    analysis = analyze(report)

    report["alerts"] = analysis["alerts"]

    report["incidents"] = analysis["incidents"]

    return report