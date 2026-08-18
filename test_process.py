from collectors.process_collector import collect_processes


def main():

    processes = collect_processes()

    print("=" * 80)
    print("SentinelIR - Process Collector Test")
    print("=" * 80)

    print(f"\nTotal Processes Collected: {len(processes)}\n")

    for process in processes[:10]:  # Show only the first 10

        print("-" * 80)

        print(f"PID          : {process.get('pid')}")
        print(f"PPID         : {process.get('ppid')}")
        print(f"Name         : {process.get('name')}")
        print(f"Executable   : {process.get('exe')}")
        print(f"User         : {process.get('username')}")
        print(f"Command Line : {process.get('cmdline')}")
        print(f"Created      : {process.get('create_time')}")

    print("\n" + "=" * 80)
    print("Process Collector Test Completed Successfully!")
    print("=" * 80)


if __name__ == "__main__":
    main()