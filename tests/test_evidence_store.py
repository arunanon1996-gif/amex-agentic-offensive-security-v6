from evidence.evidence_store import EvidenceStore


def main():
    store = EvidenceStore()

    assessment_id = "test-persistent-001"

    store.add(
        assessment_id=assessment_id,
        evidence_type="observation",
        source="test",
        data={
            "message": "Port 3000 is open",
            "port": 3000,
        },
    )

    store.add(
        assessment_id=assessment_id,
        evidence_type="decision",
        source="agent",
        data={
            "decision": "Investigate HTTP service",
            "reason": "An exposed web service was detected.",
        },
    )

    records = store.get_all(assessment_id)

    print()
    print("======================================")
    print(" PERSISTENT EVIDENCE TEST")
    print("======================================")

    for record in records:
        print(record)


if __name__ == "__main__":
    main()