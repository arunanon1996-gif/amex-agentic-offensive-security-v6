from tools.nmap_adapter import NmapAdapter


def main():

    print()
    print("======================================")
    print(" NMAP SERVICE VERSION TEST")
    print("======================================")

    adapter = NmapAdapter()

    result = adapter.scan(
        target="localhost",
        ports=[3000],
    )

    print()
    print("Nmap result:")
    print(adapter.to_json(result))

    assert result.return_code == 0

    assert len(result.ports) >= 1

    port = result.ports[0]

    assert port.port == 3000

    assert port.state == "open"

    print()
    print("Detected service:", port.service)
    print("Detected version:", port.version)

    print()
    print("Nmap service/version test PASSED.")


if __name__ == "__main__":
    main()