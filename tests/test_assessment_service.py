from app.assessment_service import AssessmentService
import uuid


def main():

    service = AssessmentService()

    # =========================================================
    # AUTHORIZED TEST
    # =========================================================

    assessment_id = str(uuid.uuid4())

    print()
    print("======================================")
    print(" AUTHORIZED TEST")
    print("======================================")

    result = service.execute(
        assessment_id=assessment_id,
        target="localhost",
        tool="nmap",
        action_count=0,
        ports=[3000],
    )

    print(result)

    assert result["status"] == "COMPLETED"
    assert result["result"]["target"] == "localhost"
    assert len(result["result"]["ports"]) >= 1

    print()
    print("Authorized test PASSED.")

    # =========================================================
    # UNAUTHORIZED TEST
    # =========================================================

    unauthorized_assessment_id = str(uuid.uuid4())

    print()
    print("======================================")
    print(" UNAUTHORIZED TEST")
    print("======================================")

    result = service.execute(
        assessment_id=unauthorized_assessment_id,
        target="example.com",
        tool="nmap",
        action_count=0,
        ports=[443],
    )

    print(result)

    assert result["status"] == "DENIED"

    print()
    print("Unauthorized test PASSED.")


if __name__ == "__main__":
    main()