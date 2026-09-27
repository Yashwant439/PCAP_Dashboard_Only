import hashlib
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from .models import AnalysisJob, CaptureSummary


class CaptureStorage:
    def __init__(self, database_path: Path, capture_directory: Path) -> None:
        self.database_path = database_path
        self.capture_directory = capture_directory
        self.capture_directory.mkdir(parents=True, exist_ok=True)
        self._initialize_database()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize_database(self) -> None:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS captures (
                    capture_id TEXT PRIMARY KEY,
                    filename TEXT NOT NULL,
                    content_type TEXT,
                    size_bytes INTEGER NOT NULL,
                    sha256 TEXT NOT NULL,
                    format TEXT NOT NULL,
                    packet_count INTEGER,
                    created_at TEXT NOT NULL,
                    analysis_status TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS analysis_jobs (
                    job_id TEXT PRIMARY KEY,
                    capture_id TEXT NOT NULL,
                    status TEXT NOT NULL,
                    progress INTEGER NOT NULL,
                    message TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(capture_id) REFERENCES captures(capture_id)
                )
                """
            )

    def save_capture(
        self,
        filename: str,
        content_type: str | None,
        content: bytes,
        capture_format: str,
    ) -> CaptureSummary:
        capture_id = str(uuid4())
        created_at = datetime.now(UTC).isoformat()
        sha256 = hashlib.sha256(content).hexdigest()
        path = self.capture_directory / f"{capture_id}.bin"
        path.write_bytes(content)
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO captures
                (capture_id, filename, content_type, size_bytes, sha256, format,
                 packet_count, created_at, analysis_status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (capture_id, filename, content_type, len(content), sha256,
                 capture_format, None, created_at, "NOT_STARTED"),
            )
        return CaptureSummary(
            capture_id=capture_id,
            filename=filename,
            content_type=content_type,
            size_bytes=len(content),
            sha256=sha256,
            format=capture_format,
            created_at=created_at,
            analysis_status="NOT_STARTED",
        )

    def list_captures(self) -> list[CaptureSummary]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM captures ORDER BY created_at DESC"
            ).fetchall()
        return [CaptureSummary(**dict(row)) for row in rows]

    def get_capture(self, capture_id: str) -> CaptureSummary | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM captures WHERE capture_id = ?", (capture_id,)
            ).fetchone()
        return CaptureSummary(**dict(row)) if row else None

    def get_capture_path(self, capture_id: str) -> Path | None:
        if self.get_capture(capture_id) is None:
            return None
        path = self.capture_directory / f"{capture_id}.bin"
        return path if path.exists() else None

    def create_job(self, capture_id: str) -> AnalysisJob:
        job_id = str(uuid4())
        created_at = datetime.now(UTC).isoformat()
        job = AnalysisJob(
            job_id=job_id,
            capture_id=capture_id,
            status="PENDING",
            progress=0,
            message="Analysis queued.",
            created_at=created_at,
        )
        with self._connect() as connection:
            connection.execute(
                """
                INSERT INTO analysis_jobs
                (job_id, capture_id, status, progress, message, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (job.job_id, job.capture_id, job.status, job.progress,
                 job.message, job.created_at),
            )
            connection.execute(
                "UPDATE captures SET analysis_status = ? WHERE capture_id = ?",
                ("QUEUED", capture_id),
            )
        return job

    def update_job(self, job_id: str, status: str, progress: int, message: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE analysis_jobs SET status = ?, progress = ?, message = ? WHERE job_id = ?",
                (status, progress, message, job_id),
            )

    def update_capture_analysis_status(self, capture_id: str, status: str, packet_count: int | None = None) -> None:
        with self._connect() as connection:
            connection.execute(
                "UPDATE captures SET analysis_status = ?, packet_count = ? WHERE capture_id = ?",
                (status, packet_count, capture_id),
            )

    def get_job(self, job_id: str) -> AnalysisJob | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM analysis_jobs WHERE job_id = ?", (job_id,)
            ).fetchone()
        return AnalysisJob(**dict(row)) if row else None
