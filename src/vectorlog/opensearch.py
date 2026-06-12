from __future__ import annotations

import json
from typing import Any

from .config import Settings, load_settings
from .embeddings import EmbeddingService


INDEX_SETTINGS = {
    "settings": {
        "index": {
            "knn": True,
            "knn.algo_param.ef_search": 100,
            "number_of_shards": 1,
            "number_of_replicas": 0,
        }
    },
    "mappings": {
        "properties": {
            "line_id": {"type": "integer"},
            "log_timestamp": {"type": "date", "format": "strict_date_optional_time"},
            "level": {"type": "keyword"},
            "event_id": {"type": "keyword"},
            "raw_message": {"type": "text", "analyzer": "standard"},
            "normalized_message": {"type": "text"},
            "event_template": {"type": "keyword"},
            "source": {"type": "keyword"},
            "embedding": {
                "type": "knn_vector",
                "dimension": 384,
                "method": {
                    "name": "hnsw",
                    "space_type": "cosinesimil",
                    "engine": "nmslib",
                    "parameters": {"ef_construction": 128, "m": 16},
                },
            },
        }
    },
}


def _client(settings: Settings):
    from opensearchpy import OpenSearch, RequestsHttpConnection

    return OpenSearch(
        hosts=[{"host": settings.opensearch_host, "port": settings.opensearch_port}],
        http_auth=(settings.opensearch_user, settings.opensearch_password),
        use_ssl=False,
        verify_certs=False,
        connection_class=RequestsHttpConnection,
        timeout=30,
    )


def ensure_index(settings: Settings | None = None) -> str:
    settings = settings or load_settings()
    client = _client(settings)
    index_name = f"{settings.opensearch_index_prefix}_logs"
    if not client.indices.exists(index=index_name):
        client.indices.create(index=index_name, body=INDEX_SETTINGS)
    return index_name


def bulk_index(
    records: list[dict[str, Any]],
    settings: Settings | None = None,
    embedder: EmbeddingService | None = None,
) -> dict[str, int]:
    settings = settings or load_settings()
    embedder = embedder or EmbeddingService(settings.model_name)
    client = _client(settings)
    index_name = ensure_index(settings)

    messages = [r["normalized_message"] for r in records]
    vectors = embedder.encode(messages)

    actions = []
    for record, vector_str in zip(records, vectors):
        # vector_str is pgvector format "[x,y,...]" — convert to list of floats
        embedding = json.loads(vector_str.replace("(", "[").replace(")", "]"))
        doc = {**record, "embedding": embedding}
        actions.append({"index": {"_index": index_name, "_id": str(record.get("id", ""))}})
        actions.append(doc)

    if not actions:
        return {"indexed": 0, "errors": 0}

    response = client.bulk(body=actions)
    errors = sum(1 for item in response["items"] if item.get("index", {}).get("error"))
    return {"indexed": len(records) - errors, "errors": errors}


def semantic_search_os(
    query: str,
    top_k: int = 20,
    level: str | None = None,
    settings: Settings | None = None,
    embedder: EmbeddingService | None = None,
) -> list[dict[str, Any]]:
    settings = settings or load_settings()
    embedder = embedder or EmbeddingService(settings.model_name)
    client = _client(settings)
    index_name = f"{settings.opensearch_index_prefix}_logs"

    vector_str = embedder.encode_one(query)
    embedding = json.loads(vector_str.replace("(", "[").replace(")", "]"))

    query_body: dict[str, Any] = {
        "size": top_k,
        "query": {
            "knn": {
                "embedding": {
                    "vector": embedding,
                    "k": top_k,
                }
            }
        },
        "_source": {"excludes": ["embedding"]},
    }

    if level and level != "ALL":
        query_body["post_filter"] = {"term": {"level": level}}

    response = client.search(index=index_name, body=query_body)
    results = []
    for hit in response["hits"]["hits"]:
        doc = hit["_source"]
        doc["similarity"] = hit["_score"]
        results.append(doc)
    return results


def delete_index(settings: Settings | None = None) -> bool:
    settings = settings or load_settings()
    client = _client(settings)
    index_name = f"{settings.opensearch_index_prefix}_logs"
    if client.indices.exists(index=index_name):
        client.indices.delete(index=index_name)
        return True
    return False


def index_stats(settings: Settings | None = None) -> dict[str, Any]:
    settings = settings or load_settings()
    client = _client(settings)
    index_name = f"{settings.opensearch_index_prefix}_logs"
    if not client.indices.exists(index=index_name):
        return {"exists": False}
    stats = client.indices.stats(index=index_name)
    count = client.count(index=index_name)
    return {
        "exists": True,
        "doc_count": count["count"],
        "store_size_bytes": stats["indices"][index_name]["total"]["store"]["size_in_bytes"],
    }
