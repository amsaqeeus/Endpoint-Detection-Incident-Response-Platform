import os
import winreg


def collect_registry_run():

    entries = []

    locations = [

        (
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Run"
        ),

        (
            winreg.HKEY_LOCAL_MACHINE,
            r"Software\Microsoft\Windows\CurrentVersion\Run"
        ),

    ]

    for hive, path in locations:

        try:

            key = winreg.OpenKey(hive, path)

            count = winreg.QueryInfoKey(key)[1]

            for i in range(count):

                name, value, _ = winreg.EnumValue(key, i)

                entries.append({

                    "location": path,

                    "name": name,

                    "value": value

                })

        except Exception:

            pass

    return entries



def collect_startup_folder():

    startup = os.path.join(

        os.getenv("APPDATA"),

        r"Microsoft\Windows\Start Menu\Programs\Startup"

    )

    entries = []

    if os.path.exists(startup):

        for file in os.listdir(startup):

            entries.append({

                "location": startup,

                "name": file,

                "value": os.path.join(startup, file)

            })

    return entries



def collect_persistence():

    report = {}

    report["registry"] = collect_registry_run()

    report["startup"] = collect_startup_folder()

    return report