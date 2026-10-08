from tools.http_adapter import HttpAdapter


def main():

    adapter = HttpAdapter()

    result = adapter.probe(
        target="localhost",
        port=3000,
    )

    print()
    print("======================================")
    print(" HTTP ADAPTER TEST")
    print("======================================")

    print(adapter.to_json(result))


if __name__ == "__main__":
    main()