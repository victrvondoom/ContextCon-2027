"""Operational store (SQLite by default; plain SQL, portable to YugabyteDB YSQL) + Meko adapter."""
import json, os, sqlite3, time, uuid, threading, httpx

DB = os.environ.get("SENTINEL_DB", os.path.join(os.path.dirname(__file__), "..", "data", "sentinel.db"))
_lock = threading.RLock()
SCHEMA = """
CREATE TABLE IF NOT EXISTS events(id TEXT PRIMARY KEY, case_id TEXT, ts INT, channel TEXT, type TEXT, account TEXT, device TEXT, ip TEXT, attrs TEXT);
CREATE TABLE IF NOT EXISTS cases(id TEXT PRIMARY KEY, wave INT, session TEXT, data TEXT, status TEXT, created REAL);
CREATE TABLE IF NOT EXISTS learning(id TEXT PRIMARY KEY, case_id TEXT, candidate TEXT, status TEXT, memory_id TEXT, reviewer TEXT, created REAL);
CREATE TABLE IF NOT EXISTS traces(id INTEGER PRIMARY KEY AUTOINCREMENT, session TEXT, case_id TEXT, agent TEXT, tool TEXT, mode TEXT, latency_ms REAL, tokens INT, summary TEXT, ts REAL);
CREATE TABLE IF NOT EXISTS memories(id TEXT PRIMARY KEY, scope TEXT, session TEXT, content TEXT, tags TEXT, created REAL);
CREATE TABLE IF NOT EXISTS bench(id INTEGER PRIMARY KEY AUTOINCREMENT, data TEXT, ts REAL);
"""
def conn():
    c = sqlite3.connect(DB, check_same_thread=False); c.row_factory = sqlite3.Row; return c
def init():
    os.makedirs(os.path.dirname(os.path.abspath(DB)), exist_ok=True)
    with _lock, conn() as c: c.executescript(SCHEMA)
def q(sql, a=(), one=False):
    with _lock, conn() as c:
        r = c.execute(sql, a); rows = [dict(x) for x in r.fetchall()] if r.description else []
    return (rows[0] if rows else None) if one else rows
def ex(sql, a=()):
    with _lock, conn() as c: c.execute(sql, a)
def reset():
    with _lock, conn() as c:
        for t in ("events","cases","learning","traces","memories","bench"): c.execute(f"DELETE FROM {t}")
def tok(x): return max(1, len(x if isinstance(x, str) else json.dumps(x)) // 4)

class Meko:
    """Meko Context Engine adapter. Real MCP (streamable HTTP, JSON-RPC) when MEKO_API_KEY is set;
    otherwise a persistent local store with identical semantics (session-private -> approved collective)."""
    URL = os.environ.get("MEKO_URL", "https://mcp.mekodata.ai/mcp")
    ALIASES = {"store": ["memory_store", "memory_add", "memory_write", "memory_save"],
               "search": ["memory_search", "memory_recall", "memory_query"],
               "promote": ["memory_promote"]}
    _tools, _sid, _live = None, None, None

    def __init__(self, session, case_id=None, agent="system"):
        self.session, self.case_id, self.agent = session, case_id, agent

    @classmethod
    def key(cls): return os.environ.get("MEKO_API_KEY")
    @classmethod
    def _rpc(cls, method, params=None, notify=False):
        h = {"Authorization": f"Bearer {cls.key()}", "Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
        if cls._sid: h["Mcp-Session-Id"] = cls._sid
        body = {"jsonrpc": "2.0", "method": method, **({"params": params} if params else {})}
        if not notify: body["id"] = uuid.uuid4().hex[:8]
        r = httpx.post(cls.URL, json=body, headers=h, timeout=20); r.raise_for_status()
        cls._sid = r.headers.get("mcp-session-id", cls._sid)
        if notify or not r.text.strip(): return {}
        t = r.text
        if "data:" in t: t = [l[5:] for l in t.splitlines() if l.startswith("data:")][-1]
        return json.loads(t).get("result", {})
    @classmethod
    def live(cls):
        if cls._live is None:
            cls._live = False
            if cls.key():
                try:
                    cls._rpc("initialize", {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "sentinelpack", "version": "1"}})
                    cls._rpc("notifications/initialized", notify=True)
                    cls._tools = {t["name"] for t in cls._rpc("tools/list").get("tools", [])}
                    cls._live = True
                except Exception as e: cls.err = str(e)
        return cls._live
    @property
    def mode(self): return "meko-mcp" if self.live() else "local-fallback"

    def _name(self, op):
        return next((n for n in self.ALIASES[op] if n in (self._tools or ())), self.ALIASES[op][0])
    def _trace(self, tool, t0, tokens, summary):
        ex("INSERT INTO traces(session,case_id,agent,tool,mode,latency_ms,tokens,summary,ts) VALUES(?,?,?,?,?,?,?,?,?)",
           (self.session, self.case_id, self.agent, tool, self.mode, round((time.time() - t0) * 1000, 1), tokens, summary[:200], time.time()))
    def _call(self, op, args):
        r = self._rpc("tools/call", {"name": self._name(op), "arguments": args})
        return "".join(c.get("text", "") for c in r.get("content", []))

    def store(self, content, tags):
        t0, mid = time.time(), "mem_" + uuid.uuid4().hex[:10]
        if self.live():
            try:
                out = self._call("store", {"content": content, "tags": tags, "metadata": {"session": self.session}})
                try: mid = json.loads(out).get("id", mid)
                except Exception: pass
            except Exception: self.__class__._live = False
        ex("INSERT INTO memories VALUES(?,?,?,?,?,?)", (mid, "session", self.session, content, json.dumps(tags), time.time()))
        self._trace("memory_store", t0, tok(content), f"private observation {mid}"); return mid

    def promote(self, mid):
        t0 = time.time()
        if self.live():
            try: self._call("promote", {"memory_id": mid})
            except Exception: self.__class__._live = False
        ex("UPDATE memories SET scope='collective' WHERE id=?", (mid,))
        self._trace("memory_promote", t0, 8, f"{mid} -> collective")

    def search(self, query, tag="ato_pattern", k=5):
        t0, hits = time.time(), []
        if self.live():
            try:
                out = self._call("search", {"query": query, "limit": k})
                for l in out.split("\n"):
                    i = l.find("{")
                    if i >= 0:
                        try: hits.append({"id": "meko", "content": json.loads(l[i:])})
                        except Exception: pass
            except Exception: self.__class__._live = False
        if not hits:  # local collective store (or Meko returned nothing parseable)
            for r in q("SELECT * FROM memories WHERE scope='collective' AND tags LIKE ? ORDER BY created DESC LIMIT ?", (f"%{tag}%", k)):
                try: hits.append({"id": r["id"], "content": json.loads(r["content"])})
                except Exception: pass
        self._trace("memory_search", t0, tok(hits), f"q='{query[:60]}' -> {len(hits)} collective hits"); return hits
