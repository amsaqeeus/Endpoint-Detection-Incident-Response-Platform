import psutil


def collect_connections():

    connections = []

    for conn in psutil.net_connections(kind="inet"):

        try:

            pid = conn.pid

            process_name = "Unknown"

            if pid:

                try:
                    process_name = psutil.Process(pid).name()
                except Exception:
                    pass

            connections.append({

                "pid": pid,

                "process": process_name,

                "local_ip": conn.laddr.ip if conn.laddr else None,

                "local_port": conn.laddr.port if conn.laddr else None,

                "remote_ip": conn.raddr.ip if conn.raddr else None,

                "remote_port": conn.raddr.port if conn.raddr else None,

                "status": conn.status

            })

        except Exception:
            continue

    return connections