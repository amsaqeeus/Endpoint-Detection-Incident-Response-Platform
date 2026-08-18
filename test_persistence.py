from collectors.persistence_collector import collect_persistence


def main():

    data = collect_persistence()

    print("=" * 80)

    print("Registry Run Keys")

    print("=" * 80)

    for item in data["registry"]:

        print()

        print("Name :", item["name"])

        print("Value:", item["value"])

    print()

    print("=" * 80)

    print("Startup Folder")

    print("=" * 80)

    for item in data["startup"]:

        print()

        print("Name :", item["name"])

        print("Path :", item["value"])


if __name__ == "__main__":

    main()