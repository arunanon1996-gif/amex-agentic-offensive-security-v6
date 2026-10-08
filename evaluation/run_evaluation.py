import json

from evaluation.harness import EvaluationHarness


if __name__ == "__main__":
    print(
        json.dumps(
            {
                "evaluation": EvaluationHarness().run_reference_cases()
            },
            indent=2,
        )
    )
