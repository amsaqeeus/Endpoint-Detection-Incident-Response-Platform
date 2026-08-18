import os
import winreg


def collect_startup():

    startup = []

    # ------------------------
    # Startup Folder
    # ------------------------

    startup_folder = os.path.join(

        os.getenv("APPDATA"),

        r"Microsoft\Windows\Start Menu\Programs\Startup"

    )

    if os.path.exists(startup_folder):

        for file in os.listdir(startup_folder):

            startup.append({

                "type": "Startup Folder",

                "name": file,

                "path": os.path.join(startup_folder, file)

            })

    # ------------------------
    # Registry Run
    # ------------------------

    try:

        key = winreg.OpenKey(

            winreg.HKEY_CURRENT_USER,

            r"Software\Microsoft\Windows\CurrentVersion\Run"

        )

        i = 0

        while True:

            try:

                name, value, _ = winreg.EnumValue(key, i)

                startup.append({

                    "type": "Registry Run",

                    "name": name,

                    "path": value

                })

                i += 1

            except OSError:

                break

    except Exception:

        pass

    return startup