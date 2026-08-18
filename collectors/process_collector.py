import psutil
from datetime import datetime


def collect_processes():

    processes = []

    for process in psutil.process_iter(
        [
            "pid",
            "ppid",
            "name",
            "exe",
            "username",
            "cmdline",
            "create_time",
        ]
    ):

        try:

            info = process.info

            cmdline = info.get("cmdline") or []

            processes.append({

                "pid": info.get("pid"),

                "ppid": info.get("ppid"),

                "name": info.get("name") or "Unknown",

                "exe": info.get("exe") or "Access Denied",

                "username": info.get("username") or "Unknown",

                "cmdline": " ".join(cmdline),

                "create_time": (
                    datetime.fromtimestamp(
                        info.get("create_time")
                    ).strftime("%Y-%m-%d %H:%M:%S")
                    if info.get("create_time")
                    else "Unknown"
                ),

            })

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess,
        ):
            pass

    return processes