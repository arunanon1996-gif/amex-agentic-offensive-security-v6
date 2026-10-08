from policy.policy_engine import PolicyEngine


def main():

    policy = PolicyEngine()

    tests = [
        ("localhost", "nmap", 0),
        ("127.0.0.1", "nmap", 0),
        ("example.com", "nmap", 0),
        ("localhost", "unknown-tool", 0),
        ("localhost", "nmap", 20),
    ]

    for target, tool, action_count in tests:

        decision = policy.authorize(
            target=target,
            tool=tool,
            action_count=action_count,
        )

        status = "ALLOW" if decision.allowed else "DENY"

        print(
            f"[{status}] "
            f"target={target} "
            f"tool={tool} "
            f"actions={action_count} "
            f"reason={decision.reason}"
        )


if __name__ == "__main__":
    main()