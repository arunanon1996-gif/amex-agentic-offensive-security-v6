from tools.csrf_validator import CsrfValidator


def main():

    print()
    print("======================================")
    print(" CSRF VALIDATOR TEST")
    print("======================================")

    validator = CsrfValidator()

    assert validator.metadata.name == "csrf_validate"
    assert validator.metadata.category == "CSRF"
    assert callable(validator.validate)

    result = validator.validate(
        target="localhost",
        port=3000,
        path="/",
        method="POST",
        body="test=value",
    )

    print()
    print("CSRF validation result:")
    print(validator.to_dict(result))

    assert result.url == "http://localhost:3000/"
    assert result.method == "POST"
    assert result.error is None or isinstance(
        result.error,
        str,
    )

    print()
    print("CSRF validator test PASSED.")


if __name__ == "__main__":
    main()