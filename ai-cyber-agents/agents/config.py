"""Central configuration: models, effort levels and scan domains."""

# Manager (high model) - plans, dispatches, dedups, scores, writes the report.
ORCHESTRATOR_MODEL = "claude-opus-5-5"
ORCHESTRATOR_EFFORT = "high"

# Workers (lower models)
SCANNER_MODEL = "claude-haiku-5-5"   # cheap, parallel web scanning
SCANNER_EFFORT = "low"
VERIFIER_MODEL = "claude-sonnet-5-5"  # cross-checks high/critical findings
VERIFIER_EFFORT = "medium"

# Guards against runaway cost
MAX_ORCHESTRATOR_TURNS = 14
MAX_WORKER_TURNS = 12
MAX_PARALLEL_WORKERS = 6
SCANNER_MAX_SEARCHES = 8
VERIFIER_MAX_SEARCHES = 6

# Default focus areas the orchestrator may assign (it can also invent its own).
DEFAULT_DOMAINS = [
    "CVEs and vulnerabilities in AI/ML frameworks and inference servers "
    "(LangChain, LlamaIndex, MLflow, Ollama, vLLM, Ray, Hugging Face libs, MCP servers)",
    "Prompt injection, jailbreak and AI-agent / MCP attack research and real-world incidents",
    "AI supply-chain threats: malicious models, poisoned datasets, typosquatted AI packages",
    "Threat actors using AI: AI-assisted phishing, deepfakes, malware development, state-actor reports",
    "Data leakage and security incidents at AI vendors and AI-powered products",
    "Government advisories, standards and regulation on AI security "
    "(CISA, NCSC, ENISA, Israel National Cyber Directorate, NIST, OWASP LLM Top 10)",
]

SEVERITIES = ["critical", "high", "medium", "low", "info"]
