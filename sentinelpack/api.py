import json, uuid
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse
from . import core, store, bench
from .store import Meko

store.init(); app = FastAPI(title="SentinelPack")
WEB = __import__("os").path.join(__import__("os").path.dirname(__file__), "..", "web", "index.html")

@app.get("/")
def index(): return FileResponse(WEB)
@app.get("/api/status")
def status(): Meko.live(); return {"meko_mode": "meko-mcp" if Meko._live else "local-fallback", "meko_url": Meko.URL, "meko_error": getattr(Meko, "err", None),
    "cases": store.q("SELECT id,wave,session,status FROM cases ORDER BY created"), "learning": store.q("SELECT id,case_id,status,memory_id,reviewer FROM learning"),
    "collective_patterns": store.q("SELECT count(*) n FROM memories WHERE scope='collective'", one=True)["n"]}
@app.post("/api/session")
def new_session(): return {"session": "sess_" + uuid.uuid4().hex[:6]}  # fresh worker: no in-process state, only Meko
@app.post("/api/wave/{wave}/run")
def run_wave(wave: int, session: str = "", seed: int = 0): return core.run_case(wave, session or "sess_" + uuid.uuid4().hex[:6], seed)
@app.post("/api/cases/{cid}/confirm")
def confirm(cid: str):
    if not store.q("SELECT 1 FROM cases WHERE id=?", (cid,)): raise HTTPException(404)
    return core.confirm(cid)
@app.post("/api/learning/{lid}/approve")
def approve(lid: str, reviewer: str = "investigator"):
    try: return core.approve(lid, reviewer)
    except ValueError as e: raise HTTPException(409, str(e))
@app.get("/api/cases/{cid}/audit", response_class=PlainTextResponse)
def audit(cid: str):
    r = core.audit(cid)
    if r is None: raise HTTPException(404)
    return r
@app.get("/api/traces")
def traces(): return store.q("SELECT * FROM traces ORDER BY id DESC LIMIT 100")
@app.post("/api/benchmark")
def benchmark(n: int = 40): return bench.run(min(n, 500))
@app.post("/api/reset")
def reset(): store.reset(); return {"ok": True}
