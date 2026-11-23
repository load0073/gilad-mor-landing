"""Offline end-to-end test: fakes the API and checks the whole agent pipeline."""
import os
import sys
import tempfile
from types import SimpleNamespace as NS

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from agents import llm, config  # noqa: E402
from agents.orchestrator import Orchestrator  # noqa: E402
from agents.report import write_all  # noqa: E402

calls = []


def tool(name, inp, i="t1"):
    return NS(type="tool_use", id=i, name=name, input=inp)


def msg(stop, *blocks):
    return NS(stop_reason=stop, content=list(blocks))


def fake_create(**kw):
    calls.append(kw["model"])
    last = kw["messages"][-1]
    first_turn = last["role"] == "user" and isinstance(last["content"], str)
    if kw["model"] == config.SCANNER_MODEL:
        if not first_turn:
            return msg("end_turn", NS(type="text", text="done"))
        return msg("tool_use", tool("record_finding", {
            "title": "RCE in ExampleLLM server", "summary": "A flaw allows code execution.",
            "category": "vulnerability", "severity_guess": "high", "affected": "ExampleLLM < 1.2",
            "published": "2026-11-20", "source_urls": ["https://example.org/advisory"]}))
    if kw["model"] == config.VERIFIER_MODEL:
        assert kw["fallbacks"] == "default"
        if not first_turn:
            return msg("end_turn", NS(type="text", text="done"))
        fid = kw["messages"][0]["content"].split("[")[1].split("]")[0]
        return msg("tool_use", tool("record_verdict", {
            "finding_id": fid, "verdict": "confirmed", "severity": "critical",
            "notes": "CVSS 9.8", "extra_sources": ["https://nvd.example/CVE-X"]}))
    raise AssertionError(kw["model"])


def fake_stream(**kw):
    calls.append(kw["model"])
    n = sum(1 for m in kw["messages"] if m["role"] == "assistant")
    if n == 0:
        return msg("tool_use", tool("dispatch_scanners", {"tasks": [
            {"agent_id": "scan-cve", "focus": "AI CVEs"}, {"agent_id": "scan-supply", "focus": "supply chain"}]}))
    if n == 1:
        return msg("tool_use", tool("verify_findings", {"finding_ids": ["F001"]}))
    return msg("tool_use", tool("submit_report", {
        "executive_summary": "תקציר", "key_trends": ["מגמה"],
        "items": [{"finding_ids": ["F001", "F002"], "title": "RCE בשרת ExampleLLM", "category": "vulnerability",
                   "severity": "critical", "summary": "פירוט", "affected": "ExampleLLM < 1.2", "recommendation": "לעדכן"},
                  {"finding_ids": ["F999"], "title": "ללא מקור", "category": "x", "severity": "low",
                   "summary": "-", "affected": "-", "recommendation": "-"}],
        "recommendations": ["המלצה"], "open_items": ["פתוח"]}))


def test_pipeline():
    llm.create, llm.stream = fake_create, fake_stream
    r = Orchestrator("2026-11-09", "2026-11-23").run()
    assert len(r["items"]) == 1, "unsourced item must be dropped"
    it = r["items"][0]
    assert it["verification"] == "confirmed"
    assert "https://nvd.example/CVE-X" in it["sources"] and "https://example.org/advisory" in it["sources"]
    assert calls.count(config.SCANNER_MODEL) == 4 and config.ORCHESTRATOR_MODEL in calls
    with tempfile.TemporaryDirectory() as d:
        paths = write_all(r, os.path.join(d, "rep"))
        html = open(paths[2], encoding="utf-8").read()
        assert 'dir="rtl"' in html and "RCE בשרת ExampleLLM" in html
    print("OK")


if __name__ == "__main__":
    test_pipeline()
