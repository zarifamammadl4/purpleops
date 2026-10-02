"""
AI-assisted detection gap triage for PurpleOps.

When a MITRE ATT&CK technique is MISSED, this sends the test command and any raw Wazuh
telemetry found near the attack's time window to an LLM, and asks it to diagnose whether
the gap is a TELEMETRY GAP (nothing was logged at all, so no rule could ever match it) or
a RULE GAP (something was logged but no existing rule matched its fields) -- and to draft
a candidate Wazuh rule when it's the latter.

This automates the same root-cause process used by hand to find the original
T1083 / T1518.001 / T1046 telemetry gaps in this lab: enabling logall/logall_json and
inspecting raw archived events instead of just the alert log.

Supports two providers, picked via AI_PROVIDER in .env:
  - "gemini"    (default) -- Google Gemini, has a free tier. Needs GEMINI_API_KEY.
  - "anthropic" -- Claude. Needs ANTHROPIC_API_KEY.
"""

import os
import time

AI_PROVIDER = os.environ.get("AI_PROVIDER", "gemini").lower()
GEMINI_MODEL = os.environ.get("PURPLEOPS_AI_MODEL", "gemini-3.8-flash")
ANTHROPIC_MODEL = os.environ.get("PURPLEOPS_AI_MODEL", "claude-sonnet-4-5")
MAX_RETRIES = 4
RETRY_DELAYS = [5, 15, 30]  # seconds, for transient errors (503 overload, rate limits)

TRIAGE_PROMPT = """You are helping triage a MITRE ATT&CK detection gap in a Wazuh SIEM lab.

Technique: {technique_id} - {technique_name} ({tactic})
Test command executed on the Windows endpoint:
{test_command}

Raw Wazuh archive events found for this agent within the correlation window:
{events_block}

Diagnose this as one of:
1. TELEMETRY GAP - no relevant event was logged at all (Sysmon/PowerShell logging doesn't
   capture this action), so no rule could ever match it.
2. RULE GAP - an event WAS logged but no existing rule matched its fields.
3. TIMING/OTHER - something else (correlation window too short, agent lag, clock skew, etc).

If it's a RULE GAP, draft a candidate Wazuh local_rules.xml <rule> block (with a MITRE
ATT&CK <mitre><id> tag for {technique_id}) that would match the event shown above. Keep it
concise and specific to the real field values shown -- don't invent fields that aren't
present in the events.

Be direct and technical. This is for a working security engineer, not a tutorial."""


def _build_prompt(scenario, raw_events):
    if raw_events:
        events_block = "\n".join(str(e) for e in raw_events[:5])
    else:
        events_block = "(no matching raw events found in the archive log for this time window)"

    return TRIAGE_PROMPT.format(
        technique_id=scenario["id"],
        technique_name=scenario["name"],
        tactic=scenario["tactic"],
        test_command=scenario["test_command"],
        events_block=events_block,
    )


def _is_transient(exc):
    """503 (overload), 429 (rate limit), and similar are worth retrying; anything else
    (bad API key, bad model name, malformed request) is not."""
    msg = str(exc)
    return any(code in msg for code in ("503", "429", "UNAVAILABLE", "RESOURCE_EXHAUSTED"))


def _triage_with_gemini(prompt):
    from google import genai

    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        raise RuntimeError(
            "GEMINI_API_KEY is not set. Get a free key at https://aistudio.google.com/apikey, "
            "add it to your .env (see .env.example), and load it, e.g.: "
            "export $(grep -v '^#' .env | xargs)"
        )
    client = genai.Client(api_key=api_key)

    last_exc = None
    for attempt in range(MAX_RETRIES):
        try:
            resp = client.models.generate_content(model=GEMINI_MODEL, contents=prompt)
            return resp.text
        except Exception as e:
            last_exc = e
            if not _is_transient(e) or attempt == MAX_RETRIES - 1:
                raise
            delay = RETRY_DELAYS[min(attempt, len(RETRY_DELAYS) - 1)]
            print(f"  (Gemini overloaded, retrying in {delay}s -- attempt {attempt + 1}/{MAX_RETRIES})")
            time.sleep(delay)
    raise last_exc


def _triage_with_anthropic(prompt):
    from anthropic import Anthropic

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError(
            "ANTHROPIC_API_KEY is not set. Add it to your .env (see .env.example) and "
            "load it, e.g.: export $(grep -v '^#' .env | xargs)"
        )
    client = Anthropic(api_key=api_key)
    resp = client.messages.create(
        model=ANTHROPIC_MODEL,
        max_tokens=1024,
        messages=[{"role": "user", "content": prompt}],
    )
    return resp.content[0].text


def triage_gap(scenario, raw_events):
    """Ask the configured LLM provider to diagnose a detection gap. Returns the analysis as text."""
    prompt = _build_prompt(scenario, raw_events)

    if AI_PROVIDER == "gemini":
        return _triage_with_gemini(prompt)
    elif AI_PROVIDER == "anthropic":
        return _triage_with_anthropic(prompt)
    else:
        raise RuntimeError(f"Unknown AI_PROVIDER '{AI_PROVIDER}'. Use 'gemini' or 'anthropic'.")


if __name__ == "__main__":
    demo_scenario = {
        "id": "T1059.001",
        "name": "PowerShell Execution",
        "tactic": "Execution",
        "test_command": "Get-Process | Select-Object -First 5",
    }
    print(f"(using provider: {AI_PROVIDER})\n")
    print(triage_gap(demo_scenario, []))
