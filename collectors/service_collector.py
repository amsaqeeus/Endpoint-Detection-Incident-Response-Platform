import psutil


def collect_services():

    services = []

    try:

        for service in psutil.win_service_iter():

            try:

                info = service.as_dict()

                services.append({

                    "name": info.get("name"),

                    "display_name": info.get("display_name"),

                    "status": info.get("status"),

                    "start_type": info.get("start_type"),

                    "username": info.get("username"),

                    "binpath": info.get("binpath"),

                })

            except Exception:
                continue

    except Exception:
        pass

    return services