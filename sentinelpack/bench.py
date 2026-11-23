"""Benchmark: stateless vs memory-augmented over N mutated attacks + benign controls. Patterns come from the real store/Meko."""
import json, time
from . import core, store
from .store import Meko

def run(n=40):
    pats = [h["content"] for h in Meko("bench", None, "audit_replay").search("account takeover sequence recovery beneficiary payout") if "seq" in h["content"]]
    rows, fp, benign_n = [], 0, n
    for s in range(n):
        ev = core.generate(2, seed=s + 100); sa, ma, _ = core.evaluate(ev, pats)
        rows.append((sa, ma, core.moved(ev, ma) if ma is not None else True, core.tok(pats), core.tok(ev)))
    for s in range(benign_n):
        ev = core.generate(2, seed=s + 900, benign=True); _, ma, _ = core.evaluate(ev, pats); fp += ma is not None
    det_m, det_s = [r for r in rows if r[1] is not None], [r for r in rows if r[0] is not None]
    lead = [r[0] - r[1] for r in rows if r[0] is not None and r[1] is not None]
    out = {"attacks": n, "benign": benign_n, "patterns_in_memory": len(pats),
           "stateless_detected": len(det_s), "memory_detected": len(det_m),
           "avg_steps_earlier": round(sum(lead) / len(lead), 2) if lead else 0,
           "attacks_stopped_before_money_moves": sum(1 for r in rows if r[1] is not None and not r[2]),
           "false_positives_memory": fp, "false_positive_rate": round(fp / benign_n, 3),
           "avg_context_tokens_with_memory": round(sum(r[3] for r in rows) / n, 1),
           "avg_full_log_tokens": round(sum(r[4] for r in rows) / n, 1)}
    out["stateless_alerts_after_money_moves"] = sum(1 for s in range(n) if (lambda ev, a: a is not None and core.moved(ev, a))(core.generate(2, seed=s + 100), core.evaluate(core.generate(2, seed=s + 100), [])[0]))
    out["token_saving_vs_raw_log"] = f"{round(100 * (1 - (out['avg_context_tokens_with_memory'] + 25) / max(1, out['avg_full_log_tokens'])))}%"
    if not pats: out["note"] = "No collective patterns yet: run Wave 1, confirm and approve first."; out["token_saving_vs_raw_log"] = None
    store.ex("INSERT INTO bench(data,ts) VALUES(?,?)", (json.dumps(out), time.time())); return out
