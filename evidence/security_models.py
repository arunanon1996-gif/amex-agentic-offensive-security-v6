from dataclasses import dataclass, asdict, field


@dataclass
class SecuritySignal:
    category: str
    name: str
    value: str
    severity_hint: str
    confidence: float
    source: str
    rationale: str


@dataclass
class SecurityAnalysis:
    analyzer: str
    target: str
    signals: list[SecuritySignal] = field(
        default_factory=list
    )

    def to_dict(self) -> dict:
        return {
            "analyzer": self.analyzer,
            "target": self.target,
            "signals": [
                asdict(signal)
                for signal in self.signals
            ],
        }