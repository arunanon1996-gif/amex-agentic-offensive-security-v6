import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class EvidenceRecord:
    assessment_id: str
    evidence_type: str
    source: str
    timestamp: str
    data: dict


class EvidenceStore:

    def __init__(
        self,
        db_path: str = "evidence/assessment.db",
    ):
        self.db_path = Path(db_path)

        # Ensure the evidence directory exists
        self.db_path.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        self._initialize_database()

    def _connect(self):
        return sqlite3.connect(self.db_path)

    def _initialize_database(self):

        with self._connect() as connection:

            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS evidence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    assessment_id TEXT NOT NULL,
                    evidence_type TEXT NOT NULL,
                    source TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    data TEXT NOT NULL
                )
                """
            )

            connection.commit()

    def add(
        self,
        assessment_id: str,
        evidence_type: str,
        source: str,
        data: dict,
    ) -> EvidenceRecord:

        timestamp = datetime.now(
            timezone.utc
        ).isoformat()

        record = EvidenceRecord(
            assessment_id=assessment_id,
            evidence_type=evidence_type,
            source=source,
            timestamp=timestamp,
            data=data,
        )

        with self._connect() as connection:

            connection.execute(
                """
                INSERT INTO evidence (
                    assessment_id,
                    evidence_type,
                    source,
                    timestamp,
                    data
                )
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    record.assessment_id,
                    record.evidence_type,
                    record.source,
                    record.timestamp,
                    json.dumps(record.data),
                ),
            )

            connection.commit()

        return record

    def add_reasoning(
        self,
        assessment_id: str,
        reasoning_type: str,
        data: dict,
    ) -> EvidenceRecord:

        return self.add(
            assessment_id=assessment_id,
            evidence_type=reasoning_type,
            source="agent",
            data=data,
        )

    def get_all(
        self,
        assessment_id: str,
    ) -> list[dict]:

        with self._connect() as connection:

            cursor = connection.execute(
                """
                SELECT
                    assessment_id,
                    evidence_type,
                    source,
                    timestamp,
                    data
                FROM evidence
                WHERE assessment_id = ?
                ORDER BY id ASC
                """,
                (assessment_id,),
            )

            rows = cursor.fetchall()

        return [
            {
                "assessment_id": row[0],
                "evidence_type": row[1],
                "source": row[2],
                "timestamp": row[3],
                "data": json.loads(row[4]),
            }
            for row in rows
        ]