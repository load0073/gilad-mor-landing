"""Worker agents running on lower models.

- Scanner  (Haiku):  searches the web on one focus area and records findings.
- Verifier (Sonnet): cross-checks findings against independent sources.

Each worker records results through a strict custom tool, so the output is
structured regardless of how much prose the model writes around it.
"""
import itertools
import logging
import threading

from . import config, llm

log = logging.getLogger(__name__)
_ids = itertools.count(1)
_ids_lock = threading.Lock()

FALLBACK_BETA = "server-side-fallback-2026-07-01"


def _next_id():
    with _ids_lock:
        return f"F{next(_ids):03d}"


RECORD_FINDING_TOOL = {
    "name": "record_finding",
    "description": (
        "Record ONE cyber-security finding related to AI that you found in a search "
        "result. Call once per distinct finding. Only record items backed by a real URL "
        "you saw in the search results, published inside the requested time window."
    ),
    "strict": True,
    "input_schema": {
        "type": "object",
        "additionalProperties": False,
        "required": ["title", "summary", "category", "severity_guess",
                     "affected", "published", "source_urls"],
        "properties": {
            "title": {"type": "string"},
            "summary": {"type": "string", "description": "2-4 factual sentences"},
            "category": {"type": "string", "enum": [
                "vulnerability", "attack_technique", "supply_chain", "threat_actor",
                "incident", "advisory_regulation", "research"]},
            "severity_guess": {"type": "string", "enum": config.SEVERITIES},
            "affected": {"type": "string", "description": "Products/vendors/versions affected, or 'n/a'"},
            "published": {"type": "string", "description": "Publication date YYYY-MM-DD, or 'unknown'"},
            "source_urls": {"type": "array", "items": {"type": "string"}},
        },
    },
}

RECORD_VERDICT_TOOL = {
    "name": "record_verdict",
    "description": "Record the verification verdict for one finding id.",
    "strict": True,
    "input_schema": {
        "type": "object",
        "additionalProperties": False,
        "required": ["finding_id", "verdict", "severity", "notes", "extra_sources"],
        "properties": {
            "finding_id": {"type": "string"},
            "verdict": {"type": "string", "enum": ["confirmed", "partially_confirmed", "unconfirmed", "false"]},
            "severity": {"type": "string", "enum": config.SEVERITIES},
            "notes": {"type": "string", "description": "What was checked and any correction"},
            "extra_sources": {"type": "array", "items": {"type": "string"}},
        },
    },
}


def _run_loop(call_kwargs, handlers, max_turns):
    """Generic manual agent loop. `handlers` maps custom tool name -> fn(input)->str."""
    messages = call_kwargs.pop("messages")
    for _ in range(max_turns):
        resp = llm.create(messages=messages, **call_kwargs)
        messages.append({"role": "assistant", "content": resp.content})

        if resp.stop_reason == "refusal":
            log.warning("worker refused: %s", getattr(resp, "stop_details", None))
            return "refused"
        if resp.stop_reason == "pause_turn":
            continue
        if resp.stop_reason != "tool_use":
            return resp.stop_reason  # end_turn / max_tokens

        results = []
        for block in resp.content:
            if block.type != "tool_use":
                continue
            fn = handlers.get(block.name)
            if fn is None:
                results.append({"type": "tool_result", "tool_use_id": block.id,
                                "content": f"unknown tool {block.name}", "is_error": True})
                continue
            try:
                out = fn(block.input)
                results.append({"type": "tool_result", "tool_use_id": block.id, "content": out})
            except Exception as e:  # tool errors go back to the model, never crash the run
                results.append({"type": "tool_result", "tool_use_id": block.id,
                                "content": f"error: {e}", "is_error": True})
        if results:  # all results in a single user message
            messages.append({"role": "user", "content": results})
    return "max_turns"


def run_scanner(agent_id, focus, since, until):
    """Haiku scanner: returns a list of finding dicts."""
    findings = []

    def record(inp):
        f = dict(inp)
        f["id"] = _next_id()
        f["found_by"] = agent_id
        findings.append(f)
        return f"recorded as {f['id']}"

    system = (
        "You are a cyber threat-intelligence scanner on a defensive research team. "
        "Your job is to find PUBLIC reporting (news, vendor advisories, CVE databases, "
        "security research blogs, government advisories) about security issues that involve "
        "AI systems. You report facts; you never write exploit code or attack instructions.\n"
        f"Time window: {since} to {until}. Ignore anything published outside it.\n"
        "Work method: run several varied searches, then call record_finding once per distinct, "
        "sourced finding (aim for 3-8 quality findings, no duplicates). "
        "When finished, reply with a one-line summary."
    )
    kwargs = dict(
        model=config.SCANNER_MODEL,
        max_tokens=16000,
        system=system,
        output_config={"effort": config.SCANNER_EFFORT},
        tools=[
            {"type": "web_search_20250305", "name": "web_search",
             "max_uses": config.SCANNER_MAX_SEARCHES},
            RECORD_FINDING_TOOL,
        ],
        messages=[{"role": "user", "content": f"Focus area: {focus}"}],
    )
    status = _run_loop(kwargs, {"record_finding": record}, config.MAX_WORKER_TURNS)
    log.info("scanner %s finished (%s) with %d findings", agent_id, status, len(findings))
    return findings, status


def run_verifier(findings):
    """Sonnet verifier: returns {finding_id: verdict dict}."""
    verdicts = {}

    def record(inp):
        verdicts[inp["finding_id"]] = dict(inp)
        return "ok"

    listing = "\n\n".join(
        f"[{f['id']}] {f['title']}\nClaim: {f['summary']}\nAffected: {f['affected']}\n"
        f"Sources: {', '.join(f['source_urls'])}" for f in findings)
    kwargs = dict(
        model=config.VERIFIER_MODEL,
        max_tokens=16000,
        system=(
            "You are a fact-checker for a defensive cyber threat-intelligence report about AI security. "
            "For each finding, check the cited source and look for at least one independent source "
            "(vendor advisory, NVD/CVE record, reputable outlet). Correct the severity if needed "
            "(CVSS where available). Call record_verdict once for EVERY finding id. "
            "Do not produce exploit details."
        ),
        output_config={"effort": config.VERIFIER_EFFORT},
        betas=[FALLBACK_BETA],
        fallbacks="default",
        tools=[
            {"type": "web_search_20260209", "name": "web_search", "max_uses": config.VERIFIER_MAX_SEARCHES},
            {"type": "web_fetch_20260209", "name": "web_fetch", "max_uses": config.VERIFIER_MAX_SEARCHES},
            RECORD_VERDICT_TOOL,
        ],
        messages=[{"role": "user", "content": f"Verify these findings:\n\n{listing}"}],
    )
    status = _run_loop(kwargs, {"record_verdict": record}, config.MAX_WORKER_TURNS)
    log.info("verifier finished (%s) with %d verdicts", status, len(verdicts))
    return verdicts, status
