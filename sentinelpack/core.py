"""Synthetic generator, detectors and the five agents."""
import json, random, time, uuid
from . import store
from .store import Meko, tok

CH = {"login_anomaly": "authentication", "new_device": "device", "recovery_request": "support",
      "recovery_modified": "identity", "beneficiary_added": "payments", "test_transfer": "payments", "large_payout": "payments"}
CHAIN = ["login_anomaly", "new_device", "recovery_request", "recovery_modified", "beneficiary_added", "test_transfer", "large_payout"]
W = {"login_anomaly": 10, "new_device": 15, "recovery_request": 10, "recovery_modified": 20, "beneficiary_added": 15, "test_transfer": 10, "large_payout": 40}
STATELESS_THRESHOLD, CORE = 75, CHAIN[:5]
BASE = 9 * 3600 + 10 * 60

def _id(r, p, n=6): return p + "".join(r.choice("0123456789abcdef") for _ in range(n))

def generate(wave, seed=0, benign=False):
    """wave 1 = canonical attack. wave 2+ = mutated: new account/device/IP/beneficiary, jittered timing, optional dropped/extra events."""
    r = random.Random(seed * 7919 + wave)
    acct, dev, ip, ben = _id(r, "acct_"), _id(r, "fp_", 8), f"{r.randint(11,198)}.{r.randint(0,255)}.{r.randint(0,255)}.{r.randint(1,254)}", _id(r, "ben_")
    gaps = [0, 2, 4, 4, 5, 3, 5] if wave == 1 else [0] + [max(1, g + r.randint(-1, 3)) for g in [2, 4, 4, 5, 3, 5][:6]]
    seq = list(CHAIN)
    if benign:  # legit customer: new phone + password reset + payment to long-known payee
        seq, gaps = ["new_device", "recovery_request", "large_payout"], [0, r.randint(3, 20), r.randint(60, 400)]
    elif wave > 1 and r.random() < .3: i = r.choice([1, 5]); del seq[i]; del gaps[i]  # attacker drops a step
    t, ev = BASE + r.randint(0, 3600) * (wave > 1), []
    for ty, g in zip(seq, gaps):
        t += g * 60
        a = {}
        if ty == "recovery_request": a = {"social_engineering": not benign, "urgency_language": not benign, "verified_by": "kba" if benign else "agent_override"}
        if ty == "recovery_modified": a = {"contact_changed": True, "recovery_changed": True}
        if ty == "beneficiary_added": a = {"new_payee": True}
        if ty == "test_transfer": a = {"amount": r.choice([1, 2, 5]) * (wave if wave > 1 else 1)}
        if ty == "large_payout": a = {"amount": r.randint(4500, 9500) if not benign else r.randint(80, 300), "beneficiary": ben if not benign else "ben_known", "payee_age_min": 8 if not benign else 40000}
        ev.append({"id": "ev_" + uuid.uuid4().hex[:8], "ts": t, "channel": CH[ty], "type": ty, "account": acct, "device": dev, "ip": ip, "attrs": a})
    return ev

# ---- detection -------------------------------------------------------------------------
def lcs(a, b):
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i, x in enumerate(a):
        for j, y in enumerate(b): d[i + 1][j + 1] = d[i][j] + 1 if x == y else max(d[i][j + 1], d[i + 1][j])
    return d[-1][-1]

def stateless(prefix):
    s = sum(W[e["type"]] for e in prefix)
    return s, s >= STATELESS_THRESHOLD

def memory_match(prefix, patterns):
    """Behavioural similarity of observed prefix to a learned pattern; ids are never compared."""
    types, best = [e["type"] for e in prefix], None
    for p in patterns:
        core = p["seq"][:5]
        sim = lcs(core, types) / len(core)
        flags = {f for e in prefix for f in e["attrs"] if e["attrs"][f] is True}
        fl = len(flags & set(p["flags"])) / max(1, len(p["flags"]))
        score = round(.75 * sim + .25 * fl, 2)
        hit = "recovery_modified" in types and sim >= .8 and fl >= .5
        if best is None or score > best["score"]: best = {"score": score, "sim": round(sim, 2), "flag_overlap": round(fl, 2), "alert": hit, "pattern": p}
    return best

def disposition(step, mem_alert, money_moved):
    if mem_alert and not money_moved: return "HOLD_FOR_REVIEW", "Block new payees + force step-up until investigator clears"
    if money_moved: return "RECOMMEND_BLOCK", "Block payout, freeze beneficiary, recall test transfer"
    return "CHALLENGE", "Step-up authentication"

def evaluate(events, patterns):
    """Walk events in order. Returns first-alert index for stateless vs memory-augmented detector."""
    s_at = m_at = m_hit = None
    for i in range(len(events)):
        pre = events[:i + 1]
        if s_at is None and stateless(pre)[1]: s_at = i
        if patterns and m_at is None:
            m = memory_match(pre, patterns)
            if m and m["alert"]: m_at, m_hit = i, m
    return s_at, m_at, m_hit

def moved(events, upto):  # money moved = payments transfer events up to and including index
    return any(e["type"] in ("test_transfer", "large_payout") for e in events[:upto + 1])

# ---- agents ----------------------------------------------------------------------------
def _t(session, case, agent, tool, summary, tokens=0):
    store.ex("INSERT INTO traces(session,case_id,agent,tool,mode,latency_ms,tokens,summary,ts) VALUES(?,?,?,?,?,?,?,?,?)",
             (session, case, agent, tool, "local", 0, tokens, summary, time.time()))

def signal_collector(session, case, raw):
    ev = sorted(raw, key=lambda e: e["ts"])
    for e in ev: store.ex("INSERT OR REPLACE INTO events VALUES(?,?,?,?,?,?,?,?,?)", (e["id"], case, e["ts"], e["channel"], e["type"], e["account"], e["device"], e["ip"], json.dumps(e["attrs"])))
    _t(session, case, "signal_collector", "normalize", f"{len(ev)} events from {len({e['channel'] for e in ev})} channels persisted")
    return ev

def correlator(session, case, ev):
    links = {"accounts": sorted({e["account"] for e in ev}), "devices": sorted({e["device"] for e in ev}), "ips": sorted({e["ip"] for e in ev}),
             "beneficiaries": sorted({e["attrs"]["beneficiary"] for e in ev if "beneficiary" in e["attrs"]}),
             "span_min": (ev[-1]["ts"] - ev[0]["ts"]) // 60, "channels": sorted({e["channel"] for e in ev})}
    _t(session, case, "correlator", "link_entities", f"{len(links['channels'])} channels over {links['span_min']}min, 1 account/device/ip cluster")
    return links

def investigator(session, case, ev, links):
    mk = Meko(session, case, "investigation")
    first = [e["type"] for e in ev[:3]]
    hits = mk.search("account takeover sequence " + " ".join(first) + " recovery beneficiary payout")  # real retrieval, once per case
    patterns = [h["content"] for h in hits if isinstance(h["content"], dict) and "seq" in h["content"]]
    s_at, m_at, m_hit = evaluate(ev, patterns)
    det = m_at if m_at is not None else s_at
    ev_used = [{"event": ev[i]["type"], "channel": ev[i]["channel"], "t": f"{(ev[i]['ts'] % 86400)//3600:02d}:{(ev[i]['ts'] % 3600)//60:02d}", "weight": W[ev[i]["type"]]} for i in range(det + 1)] if det is not None else []
    disp = disposition(det, m_at is not None, moved(ev, det)) if det is not None else ("ALLOW", "No attack pattern")
    mem_gain = None if (m_at is None or s_at is None) else s_at - m_at
    _t(session, case, "investigation", "reason", f"stateless alert @{s_at}, memory alert @{m_at}, retrieved {len(patterns)} patterns", tok(patterns))
    return {"stateless_alert_step": s_at, "memory_alert_step": m_at, "steps_earlier": mem_gain,
            "money_prevented": (m_at is not None and (s_at is None or not moved(ev, m_at))),
            "disposition": disp[0], "action": disp[1], "evidence": ev_used, "retrieved": patterns,
            "learned_contribution": {k: m_hit[k] for k in ("score", "sim", "flag_overlap")} if m_hit else None,
            "meko_mode": mk.mode, "context_tokens": tok(patterns), "full_log_tokens": tok(ev)}

def learning_curator(session, case, ev):
    """Builds a de-identified, behaviour-only candidate. Nothing is shared until approved."""
    flags = sorted({f for e in ev for f, v in e["attrs"].items() if v is True and f not in ("new_payee",)} | {"new_payee"})
    gaps = [(b["ts"] - a["ts"]) // 60 for a, b in zip(ev, ev[1:])]
    cand = {"kind": "ato_pattern", "name": "recovery-takeover-to-new-payee", "seq": [e["type"] for e in ev], "flags": flags,
            "gap_max_min": max(gaps), "payee_age_min_at_payout": ev[-1]["attrs"].get("payee_age_min"), "confidence": "investigator_confirmed"}
    _t(session, case, "learning_curator", "build_candidate", "de-identified pattern (no account/device/ip/beneficiary ids)", tok(cand)); return cand

def audit(case_id):
    c = store.q("SELECT * FROM cases WHERE id=?", (case_id,), one=True)
    if not c: return None
    d, L = json.loads(c["data"]), store.q("SELECT * FROM learning WHERE case_id=?", (case_id,))
    tr = store.q("SELECT agent,tool,mode,latency_ms,tokens,summary FROM traces WHERE case_id=? ORDER BY id", (case_id,))
    r, md = d["result"], []
    md.append(f"# Audit dossier — {case_id}\n\nWave {c['wave']} · session `{c['session']}` · status **{c['status']}**\n")
    md.append(f"## Decision\n**{r['disposition']}** — {r['action']}\n\n- Stateless detector alert at step: {r['stateless_alert_step']}\n- Memory-augmented alert at step: {r['memory_alert_step']} ({r['steps_earlier']} steps earlier; money moved before alert: {not r['money_prevented']})\n- Meko mode: `{r['meko_mode']}`\n")
    md.append("## Evidence\n" + "\n".join(f"- {e['t']} {e['channel']}/{e['event']} (+{e['weight']})" for e in r["evidence"]))
    md.append("\n## Prior learning used\n" + ("\n".join(f"- pattern `{p['name']}` seq={p['seq'][:5]} similarity {r['learned_contribution']}" for p in r["retrieved"]) or "- none (cold start)"))
    md.append("\n## Learning lifecycle\n" + ("\n".join(f"- {l['id']}: {l['status']} memory={l['memory_id']} reviewer={l['reviewer']}" for l in L) or "- no candidate"))
    md.append("\n## Decision trace\n| agent | tool | mode | ms | tokens | summary |\n|--|--|--|--|--|--|\n" + "\n".join(f"| {t['agent']} | {t['tool']} | {t['mode']} | {t['latency_ms']} | {t['tokens']} | {t['summary']} |" for t in tr))
    return "\n".join(md)

def run_case(wave, session, seed=0):
    case = f"case_w{wave}_" + uuid.uuid4().hex[:6]
    ev = signal_collector(session, case, generate(wave, seed)); links = correlator(session, case, ev)
    res = investigator(session, case, ev, links)
    out = {"id": case, "wave": wave, "session": session, "events": ev, "links": links, "result": res}
    store.ex("INSERT INTO cases VALUES(?,?,?,?,?,?)", (case, wave, session, json.dumps(out), "open", time.time())); return out

def confirm(case_id):
    c = store.q("SELECT * FROM cases WHERE id=?", (case_id,), one=True); d = json.loads(c["data"])
    cand = learning_curator(c["session"], case_id, d["events"]); lid = "lrn_" + uuid.uuid4().hex[:6]
    mid = Meko(c["session"], case_id, "learning_curator").store(json.dumps(cand), ["ato_pattern", "candidate"])
    store.ex("INSERT INTO learning VALUES(?,?,?,?,?,?,?)", (lid, case_id, json.dumps(cand), "pending_approval", mid, None, time.time()))
    store.ex("UPDATE cases SET status='confirmed' WHERE id=?", (case_id,)); return {"id": lid, "candidate": cand, "status": "pending_approval", "memory_id": mid}

def approve(lid, reviewer):
    l = store.q("SELECT * FROM learning WHERE id=?", (lid,), one=True)
    if not l or l["status"] != "pending_approval": raise ValueError("not pending")
    c = store.q("SELECT session FROM cases WHERE id=?", (l["case_id"],), one=True)
    Meko(c["session"], l["case_id"], "learning_curator").promote(l["memory_id"])
    store.ex("UPDATE learning SET status='promoted',reviewer=? WHERE id=?", (reviewer, lid))
    return {"id": lid, "status": "promoted", "memory_id": l["memory_id"], "scope": "collective"}
