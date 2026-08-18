from collectors.task_collector import collect_scheduled_tasks


tasks = collect_scheduled_tasks()

print("=" * 80)
print("Scheduled Tasks")
print("=" * 80)

print(f"Found {len(tasks)} tasks\n")

for task in tasks[:10]:
    print(task.get("TaskName"))