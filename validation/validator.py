from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(frozen=True)
class ValidatorMetadata:
    """
    Describes a security validation capability without
    coupling the agent core to a specific vulnerability type.
    """

    name: str
    description: str
    category: str


class SecurityValidator(Protocol):
    """
    Generic contract for controlled offensive-security validators.

    A validator:
    - receives an authorized target
    - performs one focused validation
    - returns structured evidence
    """

    metadata: ValidatorMetadata

    def validate(
        self,
        target: str,
        **parameters: Any,
    ) -> Any:
        ...