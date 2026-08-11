# Vulnerability Triage Agent — Reconnaissance Spike

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

- **Java 11+ and Maven** on PATH (`mvn -version` to check)
- **Python 3.10+**
- A free Gemini API key from [Google AI Studio](https://aistudio.google.com/apikey)

```bash
uv venv
uv sync
cp .env.example .env
```

This creates a project-local `.venv` managed by uv. Re-run `uv sync` when
dependencies change; the environment stays isolated to this folder.

## Run it

```bash
uv run python scanner/scan.py

# 2. Run the triage agent over every alert found
uv run python agent/run_triage.py
```
