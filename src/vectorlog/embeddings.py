from __future__ import annotations

from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

from tqdm import tqdm

from .config import Settings, load_settings
from .db import connect
from .text import vector_to_pg

_LRU_MAXSIZE = 2048


@dataclass
class EmbeddingService:
    model_name: str
    device: str = "cpu"
    _cache: dict[str, str] = field(default_factory=dict, init=False, repr=False)

    def __post_init__(self) -> None:
        from sentence_transformers import SentenceTransformer

        self.model = SentenceTransformer(self.model_name, device=self.device)

    def encode(self, texts: list[str], batch_size: int = 128) -> list[str]:
        uncached = [t for t in texts if t not in self._cache]
        if uncached:
            # deduplicate before encoding
            unique = list(dict.fromkeys(uncached))
            vectors = self.model.encode(
                unique,
                batch_size=batch_size,
                normalize_embeddings=True,
                show_progress_bar=False,
            )
            for text, vec in zip(unique, vectors):
                self._cache[text] = vector_to_pg(vec.tolist())
            # evict oldest entries if cache grows too large
            if len(self._cache) > _LRU_MAXSIZE:
                oldest = list(self._cache.keys())[: len(self._cache) - _LRU_MAXSIZE]
                for k in oldest:
                    del self._cache[k]
        return [self._cache[t] for t in texts]

    def encode_one(self, text: str) -> str:
        return self.encode([text], batch_size=1)[0]

    @classmethod
    def from_settings(cls, settings: Settings) -> "EmbeddingService":
        return cls(model_name=settings.model_name, device=settings.embedding_device)


def generate_embeddings(
    settings: Settings | None = None,
    batch_size: int | None = None,
    limit_texts: int | None = None,
    embedder: EmbeddingService | None = None,
) -> dict[str, Any]:
    settings = settings or load_settings()
    batch_size = batch_size or settings.embedding_batch_size
    embedder = embedder or EmbeddingService.from_settings(settings)

    with connect(settings) as conn:
        with conn.cursor() as cur:
            sql = """
                SELECT
                    le.normalized_message,
                    MIN(le.event_id) AS representative_event_id,
                    MIN(le.level) AS representative_level,
                    COUNT(*) AS occurrences
                FROM log_entries le
                LEFT JOIN message_embeddings me
                    ON me.normalized_message = le.normalized_message
                WHERE me.normalized_message IS NULL
                GROUP BY le.normalized_message
                ORDER BY COUNT(*) DESC
            """
            if limit_texts:
                sql += " LIMIT %s"
                cur.execute(sql, (limit_texts,))
            else:
                cur.execute(sql)
            rows = cur.fetchall()

        updated_logs = 0
        updated_texts = 0
        for start in tqdm(range(0, len(rows), batch_size), desc="Embeddings"):
            batch = rows[start : start + batch_size]
            texts = [row[0] for row in batch]
            vectors = embedder.encode(texts, batch_size=batch_size)
            with conn.cursor() as cur:
                for row, vector in zip(batch, vectors):
                    text, event_id, level, occurrences = row
                    cur.execute(
                        """
                        INSERT INTO message_embeddings (
                            normalized_message, representative_event_id,
                            representative_level, occurrences, embedding, updated_at
                        )
                        VALUES (%s, %s, %s, %s, %s::vector, NOW())
                        ON CONFLICT (normalized_message)
                        DO UPDATE SET
                            representative_event_id = EXCLUDED.representative_event_id,
                            representative_level = EXCLUDED.representative_level,
                            occurrences = EXCLUDED.occurrences,
                            embedding = EXCLUDED.embedding,
                            updated_at = NOW()
                        """,
                        (text, event_id, level, occurrences, vector),
                    )
                    updated_logs += occurrences
                    updated_texts += 1

    return {"distinct_texts": updated_texts, "covered_logs": updated_logs}
