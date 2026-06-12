# Changelog

## [2.0.0] — 2024-06-12

### Added
- OpenSearch 2.x k-NN backend (`opensearch.py`) with HNSW index (m=16, ef=128, cosine similarity)
- Multi-source log parser (`parsers.py`) — OpenSSH, Syslog RFC5424, Windows Event, generic auto-detect
- Isolation Forest anomaly detector (`anomaly.py`) trained on embedding clusters
- Offline threat intelligence enrichment (`threat_intel.py`) — IP reputation, bogon detection, risk scoring
- Alert dispatcher (`alert.py`) — severity threshold filtering, SMTP email delivery
- LRU cache in `EmbeddingService` to avoid re-encoding repeated messages
- GPU device support (`EMBEDDING_DEVICE=cuda`) in embedding service
- GitHub Actions CI — pytest matrix (Python 3.10/3.11), ruff lint, docker-compose validation
- Grafana dashboard JSON template for security analytics
- `ARCHITECTURE.md` — Mermaid component diagram, data flow, DB schema, performance table
- `CONTRIBUTING.md` — dev setup, test instructions, PR guidelines
- OpenSearch Dashboards service in `docker-compose.yml`
- Health checks for PostgreSQL and OpenSearch containers

### Changed
- Package renamed from `tp5_log_search` to `vectorlog`
- CLI command renamed from `tp5-log-search` to `vectorlog`
- Default database renamed to `vectorlogdb` (user: `vectorlog`)
- `Settings` extended with OpenSearch, anomaly, and alert configuration fields
- `EmbeddingService` now accepts `device` parameter for GPU support

### Fixed
- `docker-compose.yml` PostgreSQL image pinned to pgvector/pgvector:pg16 for stability

## [1.0.0] — 2024-01-01

Initial release — Spark ETL pipeline, pgvector semantic search, FastAPI REST, Streamlit UI.
