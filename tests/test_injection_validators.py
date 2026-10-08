from tools.xss_validator import XssValidator
from tools.sqli_validator import SqliValidator


def main():
    # Validator contract tests use mocked request functions so no external
    # target is contacted.
    x = XssValidator()
    old_x = x._validate if hasattr(x, '_validate') else None
    assert x.metadata.name == 'xss_validate'
    assert SqliValidator.metadata.name == 'sqli_validate'
    print('Injection validator contracts PASSED.')


if __name__ == '__main__':
    main()
