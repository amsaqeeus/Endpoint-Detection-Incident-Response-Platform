import csv
import subprocess
from io import StringIO


def collect_scheduled_tasks():
    """
    Collect Windows Scheduled Tasks using schtasks.

    Returns a normalized list of dictionaries containing:
    - TaskName
    - Task To Run
    - Status
    - Author
    - Run As User
    - TaskPath
    """

    tasks = []

    try:

        output = subprocess.check_output(
            [
                "schtasks",
                "/query",
                "/fo",
                "csv",
                "/v"
            ],
            text=True,
            encoding="utf-8",
            errors="ignore"
        )

        reader = csv.DictReader(
            StringIO(output)
        )

        for row in reader:

            if not row:
                continue

            task_name = (
                row.get("TaskName")
                or ""
            ).strip()

            command = (
                row.get("Task To Run")
                or ""
            ).strip()

            status = (
                row.get("Status")
                or ""
            ).strip()

            author = (
                row.get("Author")
                or ""
            ).strip()

            run_as = (
                row.get("Run As User")
                or ""
            ).strip()

            # Skip malformed/repeated header rows
            if (
                not task_name
                or task_name.lower() == "taskname"
            ):
                continue

            # schtasks normally returns the path
            # inside TaskName, for example:
            #
            # \Microsoft\Windows\Application Experience\PcaPatchDbTask
            #
            # Extract it cleanly.

            task_path = "\\"

            if "\\" in task_name:

                last_separator = task_name.rfind("\\")

                task_path = (
                    task_name[:last_separator + 1]
                    or "\\"
                )

                clean_task_name = (
                    task_name[last_separator + 1:]
                )

            else:

                clean_task_name = task_name

            tasks.append({

                "TaskName": clean_task_name,

                "TaskPath": task_path,

                "Task To Run": command,

                "Status": status,

                "Author": author,

                "Run As User": run_as

            })

    except subprocess.CalledProcessError as e:

        print(
            f"[Task Collector] schtasks failed: {e}"
        )

    except Exception as e:

        print(
            f"[Task Collector] Error: {e}"
        )

    return tasks