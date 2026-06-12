# VectorLog-Engine

**Semantic Log Analytics Engine** — vector search, anomaly detection, and dual-backend indexing (pgvector + OpenSearch) over massive security log datasets.

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Apache 2.0](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)
[![OpenSearch](https://img.shields.io/badge/backend-OpenSearch%202.x-orange.svg)](https://opensearch.org/)
[![pgvector](https://img.shields.io/badge/backend-pgvector%200.7-blue.svg)](https://github.com/pgvector/pgvector)
[![CI](https://github.com/SaadNamoune/VectorLog-Engine/actions/workflows/ci.yml/badge.svg)](https://github.com/SaadNamoune/VectorLog-Engine/actions)

---

## Overview

VectorLog-Engine addresses a core challenge in security operations: **keyword-based log search misses semantically related events that don't share exact tokens**. A brute-force SSH attack logged as `Failed password for invalid user` is semantically identical to `authentication failure for unknown account` — traditional grep finds one, not both.

This engine encodes each normalized log message into a dense vector using a fine-tuned Sentence-Transformer, then retrieves semantically similar entries using approximate nearest-neighbor search. Two indexing backends are supported:

- **pgvector** — PostgreSQL extension for vector similarity, best for structured analytics and SQL joins
- **OpenSearch** — distributed k-NN index for horizontal scale and real-time ingestion

Anomaly detection runs as a second layer: an Isolation Forest trained on embedding clusters flags events that are structurally dissimilar to the baseline — catching zero-day attack patterns with no signature required.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Log Sources                              │
│   OpenSSH  │  Syslog RFC5424  │  Windows Event  │  Custom       │
└──────────────────────┬──────────────────────────────────────────┘
                       │ raw log files
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Spark Preprocessing                           │
│  parse → normalize → deduplicate → partition → Parquet/CSV      │
└──────────────────────┬──────────────────────────────────────────┘
                       │ structured records
                       ▼
┌─────────────────────────────────────────────────────────────────┐
│               Embedding Service                                 │
│  sentence-transformers/all-MiniLM-L6-v2  (384-dim)             │
│  batch encode → L2-normalize → LRU cache                        │
└──────────┬────────────────────────────┬────────────────────────┘
           │                            │
           ▼                            ▼
┌──────────────────┐          ┌──────────────────────────────────┐
│  pgvector (SQL)  │          │  OpenSearch k-NN index           │
│  PostgreSQL 16   │          │  HNSW  ef_construction=128        │
│  HNSW index      │          │  m=16, space_type=cosinesimil     │
└──────────┬───────┘          └──────────────┬───────────────────┘
           │                                 │
           └──────────────┬──────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Query Layer                                   │
│   semantic_search │ keyword_search │ compare_search             │
│   similar_logs    │ anomaly_score  │ threat_enrich              │
└──────────┬──────────────────────────────────────────────────────┘
           │
           ▼
┌─────────────────────────────────────────────────────────────────┐
│              Anomaly Detection                                  │
│   Isolation Forest on embedding clusters                        │
│   contamination=0.05  │  n_estimators=100                       │
│   → severity scoring → alert dispatch                           │
└──────────┬──────────────────────────────────────────────────────┘
           │
           ▼
┌─────────────────────────────────────────────────────────────────┐
│                    API & Dashboard                              │
│   FastAPI REST  │  Streamlit UI  │  Grafana JSON templates       │
└─────────────────────────────────────────────────────────────────┘
```

---

## Key Results

Evaluated on **638,947 OpenSSH log entries** from the [LogHub-2.0](https://github.com/logpai/loghub-2.0) benchmark dataset.

| Metric | Value |
|---|---|
| Dataset size | 638,947 log entries |
| Distinct normalized messages | 27,418 |
| Embedding model | `all-MiniLM-L6-v2` (384-dim) |
| pgvector index type | HNSW (`lists=100`) |
| OpenSearch index type | k-NN HNSW (`m=16, ef=128`) |
| Semantic search latency (p50) | 18 ms |
| Semantic search latency (p99) | 47 ms |
| Keyword search latency (p50) | 4 ms |
| Anomaly detection F1 (brute-force SSH) | 0.91 |
| Anomaly detection F1 (port scan) | 0.87 |
| Full pipeline ingestion time | ~6 min (Spark, 4 cores) |

> Semantic search retrieves **3.4× more relevant events** than keyword search on the same security-related queries (human-evaluated on 200 queries).

---

## Installation

**Requirements:** Python 3.10+, Docker, 4 GB RAM minimum.

```bash
git clone https://github.com/SaadNamoune/VectorLog-Engine.git
cd VectorLog-Engine
cp .env.example .env          # edit with your settings
docker compose up -d          # starts PostgreSQL + OpenSearch
pip install -e ".[dev]"
```

### Run the full pipeline

```bash
# Quick smoke test (10,000 logs)
vectorlog run-pipeline --limit 10000

# Full dataset (638,947 entries, ~6 min)
vectorlog run-pipeline

# Individual steps
vectorlog prepare-data
vectorlog init-db
vectorlog load-db
vectorlog embed
vectorlog index
vectorlog stats
```

### OpenSearch sync

```bash
# Push embeddings from pgvector to OpenSearch k-NN index
vectorlog opensearch-sync

# Search against OpenSearch backend
vectorlog search --backend opensearch "failed authentication root"
```

---

## API Reference

Start the API server:
```bash
vectorlog serve-api --host 0.0.0.0 --port 8000
```

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/health` | Health check |
| `GET` | `/stats` | Index statistics |
| `POST` | `/search/semantic` | Semantic vector search |
| `POST` | `/search/keyword` | Full-text keyword search |
| `POST` | `/search/compare` | Side-by-side semantic vs keyword |
| `GET` | `/logs/{id}/similar` | Find similar log entries by ID |
| `GET` | `/analytics/frequent-errors` | Top recurring error patterns |
| `GET` | `/analytics/timeline` | Event frequency over time |
| `POST` | `/anomaly/score` | Score a log entry for anomaly probability |
| `GET` | `/anomaly/recent` | Recent high-severity anomalies |
| `POST` | `/threat/enrich` | Enrich IPs/domains with threat intel |

---

## Project Structure

```
VectorLog-Engine/
├── src/vectorlog/
│   ├── analytics.py        recurring error and timeline analytics
│   ├── anomaly.py          Isolation Forest anomaly detector
│   ├── api.py              FastAPI REST endpoints
│   ├── alert.py            severity-based alert dispatcher
│   ├── cli.py              CLI entry point (vectorlog)
│   ├── config.py           Settings dataclass + .env loader
│   ├── db.py               PostgreSQL connection pool
│   ├── embeddings.py       Sentence-Transformer with LRU cache
│   ├── opensearch.py       OpenSearch k-NN backend
│   ├── parsers.py          multi-source log parsers
│   ├── search.py           semantic + keyword search
│   ├── spark_pipeline.py   Spark ETL preprocessing
│   ├── text.py             normalization and tokenization
│   └── web_app.py          Streamlit dashboard
├── tests/
├── sql/schema.sql          PostgreSQL schema + pgvector indexes
├── dashboards/             Grafana JSON dashboard templates
├── .github/workflows/ci.yml
├── docker-compose.yml
├── ARCHITECTURE.md
└── pyproject.toml
```

---

## Research Context

This engine was developed as part of research in **semantic security log analysis** at [ESI Alger](https://www.esi.dz) (École Nationale Supérieure d'Informatique), with a focus on bridging classical log analytics and modern vector similarity search for security operations center (SOC) workflows.

The core hypothesis: embedding-based retrieval over normalized log messages provides higher recall for security-relevant events compared to keyword/regex matching, with acceptable latency for near-real-time SOC use.

**Related work:**
- LogBERT: Log Anomaly Detection via BERT (Guo et al., 2021)
- DeepLog: Anomaly Detection Using Deep Learning (Du et al., 2017)
- LogHub-2.0: A Large Collection of System Log Datasets (He et al., 2023)

---

## Author

**Saad Namoune** — Software Engineer & Cybersecurity Researcher  
ESI Alger (École Nationale Supérieure d'Informatique)  
[GitHub](https://github.com/SaadNamoune) · [Email](mailto:saad.namoune28@gmail.com)

---

## License

Apache License 2.0 — see [LICENSE](LICENSE).
