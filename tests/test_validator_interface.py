from tools.cors_validator import CorsValidator
from validation.validator import (
    SecurityValidator,
    ValidatorMetadata,
)


def main():

    print()
    print("======================================")
    print(" VALIDATOR INTERFACE TEST")
    print("======================================")

    validator = CorsValidator()

    # ---------------------------------------------------------
    # Metadata contract
    # ---------------------------------------------------------

    assert isinstance(
        validator.metadata,
        ValidatorMetadata,
    )

    assert validator.metadata.name == "cors_validate"

    assert validator.metadata.category == "CORS"

    assert (
        validator.metadata.description
        == "Validate CORS behavior using a controlled external Origin."
    )

    # ---------------------------------------------------------
    # Structural validator contract
    # ---------------------------------------------------------

    # SecurityValidator is a Protocol, so verify that the
    # existing CORS implementation provides the required API.
    assert hasattr(validator, "metadata")
    assert callable(validator.validate)

    # ---------------------------------------------------------
    # Existing CORS behavior must remain unchanged
    # ---------------------------------------------------------

    result = validator.validate(
        target="localhost",
        port=3000,
        origin="https://attacker.example",
    )

    assert result.status_code == 200

    assert (
        result.access_control_allow_origin
        == "*"
    )

    assert result.wildcard_detected is True

    assert result.error is None

    print()
    print("Validator interface test PASSED.")


if __name__ == "__main__":
    main()