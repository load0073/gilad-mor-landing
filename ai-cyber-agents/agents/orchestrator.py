"""Orchestrator agent (Opus) - manages the low-model workers and writes the report.

Flow the orchestrator drives through its tools:
  1. dispatch_scanners  -> parallel Haiku scanners, one per focus area
  2. verify_findings    -> Sonnet verifier on the important findings
  3. submit_report      -> final structured report (Hebrew), merged by finding id
Source URLs in the final report always come from the workers' records, never
from the orchestrator's own text, so they cannot be invented at report time.
"""
import json
import logging
from concurrent.futures import ThreadPoolExecutor

from . import config, llm, workers

log = logging.getLogger(__name__)

DISPATCH_TOOL = {
    "name": "dispatch_scanners",
    "description": (
        "Launch parallel scanner agents (fast, low-cost model with web search). "
        f"Each task gets its own agent. Max {config.MAX_PARALLEL_WORKERS} tasks per call. "
        "Returns every finding recorded, with ids."
    ),
    "eager_input_streaming": True,
    "input_schema": {
        "type": "object",
        "additionalProperties": False,
        "required": ["tasks"],
        "properties": {"tasks": {"type": "array", "items": {
            "type": "object", "additionalProperties": False,
            "required": ["agent_id", "focus"],
            "properties": {
                "agent_id": {"type": "string", "description": "short name e.g. scan-cve"},
                "focus": {"type": "string", "description": "precise focus area + search hints"},
            }}}},
    },
}

VERIFY_TOOL = {
    "name": "verify_findings",
    "description": (
        "Send findings to the verifier agent (mid-tier model, web search + fetch) to confirm "
        "facts and severity. Use for every critical/high finding and anything doubtful."
    ),
    "eager_input_streaming": True,
    "input_schema": {
        "type": "object", "additionalProperties": False, "required": ["finding_ids"],
        "properties": {"finding_ids": {"type": "array", "items": {"type": "string"}}},
    },
}

SUBMIT_TOOL = {
    "name": "submit_report",
    "description": "Submit the final report. Call exactly once, at the end. All text in Hebrew.",
    "eager_input_streaming": True,
    "input_schema": {
        "type": "object", "additionalProperties": False,
        "required": ["executive_summary", "key_trends", "items", "recommendations", "open_items"],
        "properties": {
            "executive_summary": {"type": "string", "description": "3-6 sentences, Hebrew"},
            "key_trends": {"type": "array", "items": {"type": "string"}},
            "items": {"type": "array", "items": {
                "type": "object", "additionalProperties": False,
                "required": ["finding_ids", "title", "category", "severity", "summary",
                             "affected", "recommendation"],
                "properties": {
                    "finding_ids": {"type": "array", "items": {"type": "string"},
                                    "description": "ids merged into this item (duplicates merged)"},
                    "title": {"type": "string"},
                    "category": {"type": "string"},
                    "severity": {"type": "string", "enum": config.SEVERITIES},
                    "summary": {"type": "string"},
                    "affected": {"type": "string"},
                    "recommendation": {"type": "string"},
                }}},
            "recommendations": {"type": "array", "items": {"type": "string"}},
            "open_items": {"type": "array", "items": {"type": "string"},
                           "description": "gaps, unverified claims, things to track next run"},
        },
    },
}


def _validate(inp, schema):
    """Minimal check of required keys (eager streaming means the API does not validate)."""
    if not isinstance(inp, dict):
        return "input is not an object"
    missing = [k for k in schema.get("required", []) if k not in inp]
    return f"missing fields: {missing}" if missing else None


class Orchestrator:
    def __init__(self, since, until, domains=None):
        self.since, self.until = since, until
        self.domains = domains or config.DEFAULT_DOMAINS
        self.findings = {}   # id -> finding dict
        self.verdicts = {}   # id -> verdict dict
        self.report = None
        self.log = []        # run log for the appendix

    # ---- tool implementations -------------------------------------------
    def _dispatch(self, inp):
        tasks = inp["tasks"][: config.MAX_PARALLEL_WORKERS]
        with ThreadPoolExecutor(max_workers=len(tasks) or 1) as pool:
            futures = [pool.submit(workers.run_scanner, t["agent_id"], t["focus"],
                                   self.since, self.until) for t in tasks]
            batch = []
            for t, fut in zip(tasks, futures):
                try:
                    found, status = fut.result()
                except Exception as e:
                    log.exception("scanner %s crashed", t["agent_id"])
                    found, status = [], f"error: {e}"
                self.log.append({"agent": t["agent_id"], "model": config.SCANNER_MODEL,
                                 "status": status, "findings": len(found)})
                for f in found:
                    self.findings[f["id"]] = f
                batch.extend(found)
        return json.dumps({"findings": batch,
                           "agents": self.log[-len(tasks):]}, ensure_ascii=False)

    def _verify(self, inp):
        ids = [i for i in inp["finding_ids"] if i in self.findings]
        if not ids:
            return "no known finding ids"
        verdicts, status = workers.run_verifier([self.findings[i] for i in ids])
        self.verdicts.update(verdicts)
        self.log.append({"agent": "verifier", "model": config.VERIFIER_MODEL,
                         "status": status, "findings": len(verdicts)})
        return json.dumps({"verdicts": verdicts, "status": status}, ensure_ascii=False)

    def _submit(self, inp):
        self.report = inp
        return "report received"

    # ---- main loop -------------------------------------------------------
    def run(self):
        handlers = {"dispatch_scanners": self._dispatch,
                    "verify_findings": self._verify,
                    "submit_report": self._submit}
        schemas = {t["name"]: t["input_schema"] for t in (DISPATCH_TOOL, VERIFY_TOOL, SUBMIT_TOOL)}
        system = (
            "You are the lead analyst of a defensive cyber threat-intelligence team. You manage "
            "worker agents that run on smaller models; you do not search the web yourself.\n"
            f"Goal: an organized report of AI-related cyber findings published {self.since} to {self.until}.\n"
            "Procedure:\n"
            "1. Split the scope into focused tasks and call dispatch_scanners (one call, all tasks in parallel).\n"
            "2. Review results. If an area is thin, dispatch one more targeted round (at most 2 rounds total).\n"
            "3. Call verify_findings with every critical/high finding and any doubtful claim.\n"
            "4. Deduplicate (merge ids describing the same issue), drop unsourced or out-of-window items, "
            "set final severity (prefer verifier's severity; drop items verified as 'false').\n"
            "5. Call submit_report once. Write all report text in Hebrew; keep product names, CVE ids "
            "and technical terms in English. Be concise, factual, action-oriented.\n"
            "Never include exploit code or step-by-step attack instructions in the report."
        )
        user = "Scope areas to cover:\n" + "\n".join(f"- {d}" for d in self.domains)
        messages = [{"role": "user", "content": user}]
        tools = [DISPATCH_TOOL, VERIFY_TOOL, SUBMIT_TOOL]

        for turn in range(config.MAX_ORCHESTRATOR_TURNS):
            resp = llm.stream(
                model=config.ORCHESTRATOR_MODEL,
                max_tokens=64000,
                system=system,
                output_config={"effort": config.ORCHESTRATOR_EFFORT},
                betas=[workers.FALLBACK_BETA],
                fallbacks="default",
                tools=tools,
                messages=messages,
            )
            messages.append({"role": "assistant", "content": resp.content})
            log.info("orchestrator turn %d: %s", turn + 1, resp.stop_reason)

            if resp.stop_reason == "refusal":
                raise RuntimeError(f"orchestrator refused: {getattr(resp, 'stop_details', None)}")
            if resp.stop_reason == "max_tokens":
                messages.append({"role": "user", "content":
                                 "Output was cut off. Continue; keep the report more concise."})
                continue
            if resp.stop_reason != "tool_use":
                if self.report:
                    break
                messages.append({"role": "user", "content": "Please call submit_report now."})
                continue

            results = []
            for block in resp.content:
                if block.type != "tool_use":
                    continue
                err = _validate(block.input, schemas.get(block.name, {}))
                if block.name not in handlers or err:
                    results.append({"type": "tool_result", "tool_use_id": block.id,
                                    "content": err or "unknown tool", "is_error": True})
                    continue
                try:
                    out = handlers[block.name](block.input)
                    results.append({"type": "tool_result", "tool_use_id": block.id, "content": out})
                except Exception as e:
                    log.exception("tool %s failed", block.name)
                    results.append({"type": "tool_result", "tool_use_id": block.id,
                                    "content": f"error: {e}", "is_error": True})
            messages.append({"role": "user", "content": results})
            if self.report:
                break

        if not self.report:
            raise RuntimeError("orchestrator did not submit a report within the turn limit")
        return self.assemble()

    def assemble(self):
        """Merge the orchestrator's report with worker records (sources, verification)."""
        items = []
        for it in self.report["items"]:
            ids = [i for i in it["finding_ids"] if i in self.findings]
            sources, verdicts, published = [], [], []
            for i in ids:
                sources += self.findings[i]["source_urls"]
                published.append(self.findings[i].get("published", "unknown"))
                if i in self.verdicts:
                    verdicts.append(self.verdicts[i]["verdict"])
                    sources += self.verdicts[i].get("extra_sources", [])
            if not sources:  # no worker-backed source -> not reportable
                continue
            items.append({**it, "finding_ids": ids,
                          "sources": list(dict.fromkeys(sources)),
                          "published": max((p for p in published if p != "unknown"), default="unknown"),
                          "verification": verdicts[0] if verdicts else "not_verified"})
        order = {s: n for n, s in enumerate(config.SEVERITIES)}
        items.sort(key=lambda x: order.get(x["severity"], 99))
        return {**self.report, "items": items, "since": self.since, "until": self.until,
                "agents": self.log,
                "models": {"orchestrator": config.ORCHESTRATOR_MODEL,
                           "scanner": config.SCANNER_MODEL, "verifier": config.VERIFIER_MODEL}}
