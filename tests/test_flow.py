import os, tempfile
os.environ["SENTINEL_DB"] = os.path.join(tempfile.mkdtemp(), "t.db"); os.environ.pop("MEKO_API_KEY", None)
from sentinelpack import core, store, bench
store.init(); store.reset()

def test_cross_session_learning():
    w1 = core.run_case(1, "sess_A")
    assert w1["result"]["memory_alert_step"] is None and w1["result"]["retrieved"] == []  # cold start
    l = core.confirm(w1["id"])
    assert "acct_" not in str(l["candidate"]) and "fp_" not in str(l["candidate"])  # de-identified
    assert Meko_search("sess_B") == []  # not shared before approval
    core.approve(l["id"], "alice")
    w2 = core.run_case(2, "sess_B", seed=3)  # different agent session, different indicators
    assert w1["links"]["devices"] != w2["links"]["devices"] and w1["links"]["ips"] != w2["links"]["ips"]
    r = w2["result"]
    assert r["retrieved"] and r["memory_alert_step"] < r["stateless_alert_step"] and r["money_prevented"]
    assert r["disposition"] == "HOLD_FOR_REVIEW"

def test_benchmark_and_no_false_positives():
    out = bench.run(30)
    assert out["memory_detected"] >= 28 and out["false_positive_rate"] == 0 and out["avg_steps_earlier"] >= 1

def Meko_search(s): return core.Meko(s).search("account takeover sequence")
