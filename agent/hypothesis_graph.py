from dataclasses import dataclass, field


@dataclass
class HypothesisNode:
    hypothesis_id: str
    statement: str
    category: str
    confidence: float
    supporting_signals: list[str] = field(
        default_factory=list
    )
    candidate_actions: list[str] = field(
        default_factory=list
    )
    status: str = "CANDIDATE"


class HypothesisGraph:

    def __init__(self):
        self.nodes: dict[str, HypothesisNode] = {}

    def add(
        self,
        hypothesis_id: str,
        statement: str,
        category: str,
        confidence: float,
        supporting_signals: list[str],
        candidate_actions: list[str],
    ):

        if hypothesis_id in self.nodes:
            return self.nodes[hypothesis_id]

        node = HypothesisNode(
            hypothesis_id=hypothesis_id,
            statement=statement,
            category=category,
            confidence=confidence,
            supporting_signals=supporting_signals,
            candidate_actions=candidate_actions,
        )

        self.nodes[hypothesis_id] = node

        return node

    def get_candidates(self) -> list[HypothesisNode]:
        return [
            node
            for node in self.nodes.values()
            if node.status == "CANDIDATE"
        ]

    def mark_validated(
        self,
        hypothesis_id: str,
        confirmed: bool,
    ):

        if hypothesis_id not in self.nodes:
            return

        self.nodes[hypothesis_id].status = (
            "CONFIRMED"
            if confirmed
            else "REJECTED"
        )

    def to_dict(self) -> dict:

        return {
            "hypotheses": [
                {
                    "hypothesis_id":
                        node.hypothesis_id,
                    "statement":
                        node.statement,
                    "category":
                        node.category,
                    "confidence":
                        node.confidence,
                    "supporting_signals":
                        node.supporting_signals,
                    "candidate_actions":
                        node.candidate_actions,
                    "status":
                        node.status,
                }
                for node in self.nodes.values()
            ]
        }