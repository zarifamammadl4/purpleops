# PurpleOps

Automated Adversary Emulation & Detection Validation Engine for a self-built Purple Team lab.

PurpleOps emulates MITRE ATT&CK techniques against a live Windows endpoint, correlates the
resulting Wazuh SIEM alerts in real time, and reports which techniques are detected, missed,
or only partially covered — closing the loop between offense and detection engineering.

## Lab architecture

- **Ubuntu 24.04** — Wazuh Manager, Indexer, and Dashboard (Wazuh 4.9.2), plus the PurpleOps
  engine itself.
- **Windows Server 2019** — Sysmon (SwiftOnSecurity config) + PowerShell Script Block Logging +
  Wazuh Agent, reachable over a Host-only network and over WinRM for remote execution.
- **PurpleOps engine** (`purpleops.py`) — a Python CLI that executes ATT&CK test scenarios,
  waits for telemetry to land, queries Wazuh's alert log, and records a DETECTED/MISSED/PARTIAL
  verdict per technique in a local SQLite database.

## What it does

1. **Emulate** — runs a scenario's test command (a scheduled task, a discovery cmdlet, a
   network scan, etc.) either manually (`run`) or fully automated over WinRM (`run-all`), with
   zero human interaction on the Windows endpoint.
2. **Correlate** — matches the attack's timestamp against Wazuh's alert stream (agent name +
   MITRE ATT&CK ID + a configurable time window), so a detection is tied to the exact test that
   triggered it rather than guessed at.
3. **Report** — `report` shows every run, `coverage` deduplicates to the best result per
   technique and lists open detection gaps, and `export-navigator` writes a MITRE ATT&CK
   Navigator layer JSON you can drop straight into the official Navigator.

## Results from this lab

Starting detection rate across 10 emulated techniques: **50%**. After root-causing the misses
(some were real rule gaps, others were telemetry gaps — PowerShell cmdlets that spawn no child
process and so generate no Sysmon Event ID 1) and writing targeted Wazuh rules against
PowerShell Script Block Logging, the rate reached **90%** (9/10), regression-tested with no
prior detections lost, and reproduced automatically end-to-end via WinRM with `run-all`.

## Setup

```bash
pip install -r requirements.txt
cp .env.example .env   # fill in your Wazuh API and Windows WinRM credentials
export $(grep -v '^#' .env | xargs)
```

## Usage

```bash
python3 purpleops.py list              # available ATT&CK scenarios
python3 purpleops.py agents            # live Wazuh agent status
python3 purpleops.py run T1057         # run one scenario manually, auto-correlate
python3 purpleops.py run-all           # run every scenario fully automated via WinRM
python3 purpleops.py report            # all recorded runs
python3 purpleops.py coverage          # deduplicated gap analysis
python3 purpleops.py export-navigator  # MITRE ATT&CK Navigator layer JSON
```

## Notes

- Credentials are read from environment variables (`WAZUH_API_PASSWORD`, `WINDOWS_PASSWORD`,
  etc.) — never hardcoded. See `.env.example`.
- This is a lab environment on an isolated network; the WinRM Basic-auth setup here is not
  intended for production use over an untrusted network.
