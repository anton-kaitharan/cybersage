# CyberSage

RAG-based cybersecurity intelligence assistant. It ingests NVD, CISA KEV, EPSS and OSV data, matches
vulnerabilities to a software inventory with deterministic version checks, prioritizes them with
rule-based scoring, and uses an LLM only to retrieve, explain, and cite.

Scope: PyPI and npm only; CVEs published from 2023-01-01 onward.

## Setup

Requirements: Python 3.11+, [uv](https://docs.astral.sh/uv/), Docker.

```bash
cp .env.example .env     # set NVD_API_KEY; change POSTGRES_PORT if 5432 is taken
uv sync
make up                  # Postgres + pgvector
make migrate             # create all tables
make test
make lint
```

If you change `POSTGRES_PORT`, update the port in `DATABASE_URL` too.

## Design principles

1. Deterministic code handles matching and scoring; the LLM never decides affected-status or priority.
2. Every generated claim cites a retrieved chunk ID, verified by code.
3. "Not found in provided sources" instead of guessing; never "you are not vulnerable".
4. Retrieved text is untrusted data, never instructions.
5. Raw source documents are kept alongside normalized records.

## Progress

- [x] Phase 0: scaffold, Docker Compose (pgvector), config, Alembic, schema + migration, smoke test
- [ ] Phase 1: ingestion (NVD, KEV, EPSS, OSV)
- [ ] Phase 2: chunking + embeddings + retrieval (`chunk`, `asset` tables)
- [ ] Phase 3: deterministic matching
- [ ] Phase 4: rule-based prioritization
- [ ] Phase 5: API + cited LLM answers with verification
- [ ] Phase 6: evaluation + UI
