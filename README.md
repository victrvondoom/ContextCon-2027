# SentinelPack — Cross-Channel Fraud Intelligence & Investigation OS
*Every incident makes the next attack harder.* ContextCon 2027 · Theme 03 (primary), 07 (audit), 08 (tokens).

## Run
```bash
pip install -r requirements.txt
export MEKO_API_KEY=...        # optional; enables the real Meko MCP at https://mcp.mekodata.ai/mcp
uvicorn sentinelpack.api:app --port 8000   # open http://localhost:8000
pytest -q
```
## Demo (buttons in the UI, in order)
1. **Wave 1** – unseen 7-event takeover (auth→device→support→identity→payments). Only the stateless detector fires, at the test transfer (money already moving).
2. **Confirm** – Learning Curator builds a *de-identified behavioural* pattern (no account/device/IP/payee IDs) and stores it as a **private** memory.
3. **Approve** – human approval gates `memory_promote` → collective memory.
4. **Wave 2** – brand-new session id, new account/device/IP/payee, jittered timing, sometimes dropped steps. The investigator performs a real `memory_search`, matches the behaviour, and alerts at the recovery change / new payee — **before money moves** (`HOLD_FOR_REVIEW`). The UI shows the retrieved pattern and the similarity that drove it.

## Architecture
`web/` single-page console → `sentinelpack/api.py` (FastAPI) → `core.py` (5 agents: Signal Collector, Correlator, Investigation, Learning Curator, Audit & Replay; sequential orchestrator) → `store.py` (`Meko` adapter + SQL operational store) · `bench.py`.
- **Meko**: JSON-RPC over MCP streamable HTTP; tools are discovered with `tools/list` (`memory_store`/`memory_search`/`memory_promote`). Every call is traced (agent, tool, mode, latency, tokens).
- **Honest fallback**: without `MEKO_API_KEY`/connectivity the adapter uses a persistent local store with the same private→approved-collective semantics, and every trace/UI label says `local-fallback`. Meko tool argument shapes are best-effort assumptions and must be verified against the live server. The fallback is the only mode exercised in this repo's tests.
- **State**: plain SQL on SQLite (`SENTINEL_DB`), kept portable for YugabyteDB YSQL; a Yugabyte/Postgres driver is not wired yet.
- **Orchestration**: plain Python pipeline (no LangGraph) — a deliberate scope cut.
- **Token efficiency**: agents receive a ~60-token pattern instead of the raw event log; measured per case and in `/api/benchmark`.
- **Audit**: `GET /api/cases/{id}/audit` — decision, evidence, retrieved learning, approval lifecycle, full tool trace.

## Benchmark (synthetic)
`POST /api/benchmark?n=40`: N mutated attacks + N benign "new phone + password reset" controls; reports detection, steps earlier, attacks stopped before money moves, false positives, token saving. Results are on synthetic data produced by this repo's generator and say nothing about real fraud performance.
