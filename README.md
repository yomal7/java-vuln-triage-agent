# Vulnerability Triage Agent — Reconnaissance Spike

A side project, **not** the SCS 4224 thesis artifact. The only goal here is
to learn two things hands-on before Phase 1 (agent core) starts:

1. What does a real dependency-vulnerability triage investigation actually
   check, step by step?
2. What does automating that with an LLM agent look like in practice?

No escalation logic, no decision-variable schema — that's deliberately out
of scope here (see D1–D6 in the Design Decisions Log for where those
belong). This spike's only output is understanding — and, as a side
benefit, a real tool taxonomy and a source of genuine advisory data that
can inform Phase 1's tool layer and Phase 3's seed scenarios later.

## How it maps to the framework diagram

```
target-project/ (real old deps)
        |
   scanner/scan.py          <-- deterministic: mvn dependency:tree -> OSV.dev
        |                       (this IS the "Vulnerability alert" box —
        v                        no LLM involved, on purpose)
  results/alerts.json
        |
   agent/run_triage.py       <-- ReAct loop: "Tool calls + event/state log"
        |                        box in the diagram, minus the escalation
        v                        check (that's Phase 2, not this spike)
  results/triage_runs/*.json <-- one verdict + full trace per alert
```

## Setup

You'll need locally (this was scaffolded in a sandbox that can't reach
OSV.dev, CISA, or the Gemini API, so it hasn't been run end-to-end —
verify the first run yourself):

- **Java 11+ and Maven** on PATH (`mvn -version` to check)
- **Python 3.10+**
- A free Gemini API key from [Google AI Studio](https://aistudio.google.com/apikey)

```bash
uv venv
uv sync
cp .env.example .env        # then paste your GOOGLE_API_KEY in
```

This creates a project-local `.venv` managed by uv. Re-run `uv sync` when
dependencies change; the environment stays isolated to this folder.

## Run it

```bash
uv run python scanner/scan.py

# 2. Run the triage agent over every alert found
uv run python agent/run_triage.py
```

Check `results/alerts.json` after step 1 — that's your real, unfiltered
advisory data (CWE, CVSS, KEV status, fix versions) for the dependencies in
`target-project/pom.xml`. Check `results/triage_runs/*.json` after step 2
for each investigation's full tool-call trace and final verdict.

## What to actually pay attention to while this runs

The point isn't the verdicts — it's watching *how* the agent gets there:

- Which tool does it reach for first, unprompted?
- Does it ever skip `search_code_usage` and go straight to a severity
  judgment from CVSS alone? (Real analysts don't — CVSS without reachability
  context is a common triage mistake worth noting.)
- For the JUnit dependency (deliberately test-scoped), does the agent's
  final recommendation actually account for scope, or does it treat every
  dependency the same regardless of exposure?
- Where does it get stuck or guess instead of using a tool? Those are your
  future D2 trigger candidates — but that's next phase's problem, not this
  spike's.

## Extending this later

- Swap `target-project/pom.xml` for a real cloned repo — `scan.py` doesn't
  care, it just needs a Maven project at the path you give it.
- The six tools in `agent/tools.py` are a reasonable first draft of the
  tool taxonomy Phase 1's tool layer will need — but treat them as a
  starting point, not a spec, once you've watched a few real runs.
