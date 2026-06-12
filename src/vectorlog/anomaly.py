from __future__ import annotations

import json
import pickle
from pathlib import Path
from typing import Any

import numpy as np

from .config import Settings, load_settings
from .db import connect
from .embeddings import EmbeddingService


_DEFAULT_MODEL_PATH = Path("models/anomaly_detector.pkl")


def _load_embeddings_matrix(settings: Settings) -> tuple[np.ndarray, list[str]]:
    with connect(settings) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT normalized_message, embedding::text FROM message_embeddings WHERE embedding IS NOT NULL"
            )
            rows = cur.fetchall()
    messages = [r[0] for r in rows]
    vectors = np.array([json.loads(r[1]) for r in rows], dtype=np.float32)
    return vectors, messages


def train(
    settings: Settings | None = None,
    model_path: Path | None = None,
) -> dict[str, Any]:
    from sklearn.ensemble import IsolationForest

    settings = settings or load_settings()
    model_path = model_path or _DEFAULT_MODEL_PATH

    X, messages = _load_embeddings_matrix(settings)
    if len(X) == 0:
        return {"trained": False, "reason": "no embeddings found"}

    clf = IsolationForest(
        n_estimators=settings.anomaly_n_estimators,
        contamination=settings.anomaly_contamination,
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X)

    model_path.parent.mkdir(parents=True, exist_ok=True)
    with open(model_path, "wb") as f:
        pickle.dump(clf, f)

    scores = clf.decision_function(X)
    n_anomalies = int(np.sum(clf.predict(X) == -1))

    return {
        "trained": True,
        "n_samples": len(X),
        "n_anomalies": n_anomalies,
        "contamination": settings.anomaly_contamination,
        "score_mean": float(scores.mean()),
        "score_std": float(scores.std()),
        "model_path": str(model_path),
    }


def score_message(
    message: str,
    model_path: Path | None = None,
    settings: Settings | None = None,
    embedder: EmbeddingService | None = None,
) -> dict[str, Any]:
    model_path = model_path or _DEFAULT_MODEL_PATH
    if not model_path.exists():
        return {"error": "model not trained — run vectorlog train-anomaly first"}

    settings = settings or load_settings()
    embedder = embedder or EmbeddingService(settings.model_name)

    with open(model_path, "rb") as f:
        clf = pickle.load(f)

    vector_str = embedder.encode_one(message)
    vector = np.array(json.loads(vector_str), dtype=np.float32).reshape(1, -1)

    raw_score = float(clf.decision_function(vector)[0])
    prediction = int(clf.predict(vector)[0])

    # Map to 0-1 anomaly probability (higher = more anomalous)
    anomaly_probability = max(0.0, min(1.0, 0.5 - raw_score))

    severity = "low"
    if anomaly_probability > 0.8:
        severity = "critical"
    elif anomaly_probability > 0.65:
        severity = "high"
    elif anomaly_probability > 0.5:
        severity = "medium"

    return {
        "message": message,
        "is_anomaly": prediction == -1,
        "anomaly_probability": round(anomaly_probability, 4),
        "raw_score": round(raw_score, 4),
        "severity": severity,
    }


def score_batch(
    messages: list[str],
    model_path: Path | None = None,
    settings: Settings | None = None,
    embedder: EmbeddingService | None = None,
) -> list[dict[str, Any]]:
    return [score_message(m, model_path=model_path, settings=settings, embedder=embedder) for m in messages]
