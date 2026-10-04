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

## LLM configuration (agent/llm.py)

The agent calls the provider directly (no gateway). Everything is set in `.env`
(see `.env.example`): `LLM_MODELS` (fallback chain, first = preferred),
`LLM_PROVIDER`, `LLM_RPM` (calls per minute), `LLM_MAX_RETRIES`.
Transient errors (408, 429, 5xx, timeouts) are retried with exponential backoff
and jitter; when a model keeps failing, the next model in the chain is used.
Every run file records the settings and which model actually answered.
To move to a paid API or another vendor, change `.env` only.

## Slot check (shadow mode)

```bash
uv run python agent/slot_report.py                              # no LLM, no API calls
uv run python agent/slot_report.py --withhold asset_criticality # simulate a missing fact
uv run python agent/run_triage.py                               # also records slot_report per run
```

`results/reachability.json` is a manual stub until the reachability engine is chosen.

## Tests

```bash
uv add --dev pytest
uv run python -m pytest
```

## Running study cases (the experiment)

```bash
# one case, real participant, terminal interface
uv run python agent/run_session.py --scenario S01 --condition micro    --participant P01
uv run python agent/run_session.py --scenario S01 --condition baseline --participant P01

# development check with a scripted "perfect analyst" (no human)
uv run python agent/run_session.py --all --condition micro --simulate
```

`micro`: agent investigates -> slot check -> up to `--max-questions` fixed-template
questions -> agent resumes the same investigation -> final verdict.
`baseline`: agent investigates -> slot check -> agent stops and hands over a raw
transcript -> the analyst decides alone.

Scenarios live in `protocol/data/scenarios.example.json` (the `expected` verdicts
there are placeholders: set the ground truth yourself). Every case writes
`results/sessions/<scenario>_<condition>_<participant>.json` with questions, answers,
accuracy and timing (analyst active time is kept apart from system wait time).