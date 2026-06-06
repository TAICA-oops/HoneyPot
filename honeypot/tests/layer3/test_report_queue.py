"""報告生成改走單一 worker 佇列,避免大量 session 同時結束時併發灌爆 Ollama。"""
from layer3 import report_generator as rg


def test_enqueue_report_processes_all_jobs_serially(monkeypatch):
    seen = []
    monkeypatch.setattr(rg, "generate_report", lambda sid, **kw: seen.append(sid))
    for sid in ["s-a", "s-b", "s-c"]:
        rg.enqueue_report(sid)
    rg._report_queue.join()   # 等佇列清空
    assert sorted(seen) == ["s-a", "s-b", "s-c"]


def test_worker_survives_a_failing_job(monkeypatch):
    seen = []

    def flaky(sid, **kw):
        if sid == "boom":
            raise RuntimeError("ollama down")
        seen.append(sid)

    monkeypatch.setattr(rg, "generate_report", flaky)
    rg.enqueue_report("boom")     # 失敗的工作不能讓 worker 掛掉
    rg.enqueue_report("ok")
    rg._report_queue.join()
    assert "ok" in seen
