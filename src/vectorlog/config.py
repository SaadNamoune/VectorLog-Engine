from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _project_path(value: str) -> Path:
    path = Path(value)
    return path if path.is_absolute() else PROJECT_ROOT / path


@dataclass(frozen=True)
class Settings:
    # PostgreSQL / pgvector
    database_url: str = "postgresql://vectorlog:vectorlog@localhost:5432/vectorlogdb"

    # OpenSearch
    opensearch_host: str = "localhost"
    opensearch_port: int = 9200
    opensearch_user: str = "admin"
    opensearch_password: str = "admin"
    opensearch_index_prefix: str = "vectorlog"

    # Embedding
    model_name: str = "sentence-transformers/all-MiniLM-L6-v2"
    embedding_batch_size: int = 128
    embedding_device: str = "cpu"

    # Search
    search_top_k: int = 20

    # Log ingestion
    log_year: int = 2024
    raw_log_path: Path = PROJECT_ROOT / "data/raw/OpenSSH/OpenSSH_full.log"
    structured_csv_path: Path = PROJECT_ROOT / "data/raw/OpenSSH/OpenSSH_full.log_structured.csv"
    templates_csv_path: Path = PROJECT_ROOT / "data/raw/OpenSSH/OpenSSH_full.log_templates.csv"
    processed_dir: Path = PROJECT_ROOT / "data/processed"

    # Anomaly detection
    anomaly_contamination: float = 0.05
    anomaly_n_estimators: int = 100

    # Alerting
    alert_smtp_host: str = ""
    alert_smtp_port: int = 587
    alert_from_email: str = ""
    alert_to_email: str = ""
    alert_severity_threshold: str = "high"

    @property
    def log_entries_csv_dir(self) -> Path:
        return self.processed_dir / "log_entries_csv"

    @property
    def log_entries_parquet_dir(self) -> Path:
        return self.processed_dir / "log_entries_parquet"

    @property
    def event_templates_csv_dir(self) -> Path:
        return self.processed_dir / "event_templates_csv"


def load_settings(env_file: str | Path | None = None) -> Settings:
    if env_file is None:
        env_file = PROJECT_ROOT / ".env"
    load_dotenv(env_file)

    return Settings(
        database_url=os.getenv("DATABASE_URL", Settings.database_url),
        opensearch_host=os.getenv("OPENSEARCH_HOST", Settings.opensearch_host),
        opensearch_port=int(os.getenv("OPENSEARCH_PORT", str(Settings.opensearch_port))),
        opensearch_user=os.getenv("OPENSEARCH_USER", Settings.opensearch_user),
        opensearch_password=os.getenv("OPENSEARCH_PASSWORD", Settings.opensearch_password),
        opensearch_index_prefix=os.getenv("OPENSEARCH_INDEX_PREFIX", Settings.opensearch_index_prefix),
        model_name=os.getenv("MODEL_NAME", Settings.model_name),
        embedding_batch_size=int(os.getenv("EMBEDDING_BATCH_SIZE", str(Settings.embedding_batch_size))),
        embedding_device=os.getenv("EMBEDDING_DEVICE", Settings.embedding_device),
        search_top_k=int(os.getenv("SEARCH_TOP_K", str(Settings.search_top_k))),
        log_year=int(os.getenv("LOG_YEAR", str(Settings.log_year))),
        raw_log_path=_project_path(os.getenv("RAW_LOG_PATH", "data/raw/OpenSSH/OpenSSH_full.log")),
        structured_csv_path=_project_path(
            os.getenv("STRUCTURED_CSV_PATH", "data/raw/OpenSSH/OpenSSH_full.log_structured.csv")
        ),
        templates_csv_path=_project_path(
            os.getenv("TEMPLATES_CSV_PATH", "data/raw/OpenSSH/OpenSSH_full.log_templates.csv")
        ),
        processed_dir=_project_path(os.getenv("PROCESSED_DIR", "data/processed")),
        anomaly_contamination=float(os.getenv("ANOMALY_CONTAMINATION", str(Settings.anomaly_contamination))),
        anomaly_n_estimators=int(os.getenv("ANOMALY_N_ESTIMATORS", str(Settings.anomaly_n_estimators))),
        alert_smtp_host=os.getenv("ALERT_SMTP_HOST", Settings.alert_smtp_host),
        alert_smtp_port=int(os.getenv("ALERT_SMTP_PORT", str(Settings.alert_smtp_port))),
        alert_from_email=os.getenv("ALERT_FROM_EMAIL", Settings.alert_from_email),
        alert_to_email=os.getenv("ALERT_TO_EMAIL", Settings.alert_to_email),
        alert_severity_threshold=os.getenv("ALERT_SEVERITY_THRESHOLD", Settings.alert_severity_threshold),
    )
