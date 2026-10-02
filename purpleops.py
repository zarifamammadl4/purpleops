#!/usr/bin/env python3
"""
PurpleOps - Automated Adversary Emulation & Detection Validation Engine
Correlates ATT&CK test scenarios with Wazuh alerts to measure detection coverage.
"""

import argparse
import json
import sqlite3
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    import wazuh_api
    HAS_API = True
except ImportError:
    HAS_API = False

try:
    import winrm_client
    HAS_WINRM = True
except ImportError:
    HAS_WINRM = False

try:
    import ai_triage
    HAS_AI = True
except ImportError:
    HAS_AI = False

DB_PATH = Path(__file__).parent / "purpleops.db"
SCENARIOS_PATH = Path(__file__).parent / "scenarios.json"
BASELINE_PATH = Path(__file__).parent / "baseline.json"
ALERTS_PATH = Path("/var/ossec/logs/alerts/alerts.json")
ARCHIVES_PATH = Path("/var/ossec/logs/archives/archives.json")
AGENT_NAME = "purpleops-windows"
AGENT_ID = "001"


def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            technique_id TEXT NOT NULL,
            technique_name TEXT,
            tactic TEXT,
            start_time TEXT,
            end_time TEXT,
            status TEXT,
            detection_time_sec REAL,
            severity_level INTEGER,
            alert_description TEXT,
            note TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    return conn


def load_scenarios():
    with open(SCENARIOS_PATH) as f:
        return json.load(f)


def find_scenario(technique_id, scenarios):
    for s in scenarios:
        if s["id"].lower() == technique_id.lower():
            return s
    return None


def parse_alert_time(ts_str):
    ts_str = ts_str.replace("Z", "+0000")
    try:
        return datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S.%f%z")
    except ValueError:
        return datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S%z")


def correlate(technique_id, start_time, window_seconds=90):
    if not ALERTS_PATH.exists():
        return None

    matches = []
    with open(ALERTS_PATH, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                continue

            agent = alert.get("agent", {})
            if agent.get("name") != AGENT_NAME:
                continue

            mitre_ids = alert.get("rule", {}).get("mitre", {}).get("id", [])
            if technique_id not in mitre_ids:
                continue

            try:
                alert_time = parse_alert_time(alert["timestamp"])
            except Exception:
                continue

            delta = (alert_time - start_time).total_seconds()
            if -10 <= delta <= window_seconds:
                matches.append((delta, alert))

    if not matches:
        return None

    matches.sort(key=lambda x: x[0])
    return matches[0]


def fetch_raw_events(agent_name, start_time, window_seconds=90, max_events=5):
    """Scan the raw archive log (requires logall/logall_json enabled on the Manager) for any
    events from this agent in the attack's time window, regardless of whether they triggered
    an alert. This is what distinguishes a telemetry gap (nothing here at all) from a rule gap
    (something here, but no rule matched it)."""
    if not ARCHIVES_PATH.exists():
        return []

    events = []
    with open(ARCHIVES_PATH, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue

            agent = ev.get("agent", {})
            if agent.get("name") != agent_name:
                continue

            try:
                ev_time = parse_alert_time(ev["timestamp"])
            except Exception:
                continue

            delta = (ev_time - start_time).total_seconds()
            if -10 <= delta <= window_seconds:
                events.append(ev)
                if len(events) >= max_events:
                    break

    return events


def record_result(scenario, result):
    conn = init_db()
    if result:
        delta, alert = result
        rule = alert.get("rule", {})
        status = "DETECTED"
        level = rule.get("level")
        desc = rule.get("description")
        conn.execute(
            "INSERT INTO results (technique_id, technique_name, tactic, start_time, end_time, "
            "status, detection_time_sec, severity_level, alert_description) VALUES (?,?,?,?,?,?,?,?,?)",
            (scenario["id"], scenario["name"], scenario["tactic"],
             datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat(),
             status, delta, level, desc)
        )
        conn.commit()
        conn.close()
        return status, level, desc, delta
    else:
        status = "MISSED"
        conn.execute(
            "INSERT INTO results (technique_id, technique_name, tactic, start_time, end_time, status) "
            "VALUES (?,?,?,?,?,?)",
            (scenario["id"], scenario["name"], scenario["tactic"],
             datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat(), status)
        )
        conn.commit()
        conn.close()
        return status, None, None, None


def cmd_list(args):
    scenarios = load_scenarios()
    print(f"\n{'ID':<14}{'Tactic':<14}{'Name'}")
    print("-" * 60)
    for s in scenarios:
        print(f"{s['id']:<14}{s['tactic']:<14}{s['name']}")
    print()


def cmd_agents(args):
    if not HAS_API:
        print("The 'requests' package is not installed. Run: pip install requests --break-system-packages")
        return
    try:
        token = wazuh_api.get_token()
        agents = wazuh_api.get_agents(token)
    except Exception as e:
        print(f"Failed to reach Wazuh API: {e}")
        return

    print(f"\n{'ID':<6}{'Name':<22}{'IP':<16}{'Status':<14}{'OS'}")
    print("-" * 75)
    for a in agents:
        os_name = a.get("os", {}).get("name", "-")
        print(f"{a.get('id',''):<6}{a.get('name',''):<22}{a.get('ip',''):<16}"
              f"{a.get('status',''):<14}{os_name}")
    print()


def check_agent_active():
    if not HAS_API:
        return
    try:
        agent = wazuh_api.get_agent_status(AGENT_ID)
        if agent and agent.get("status") != "active":
            print(f"WARNING: agent '{AGENT_NAME}' status is '{agent.get('status')}' (not active).")
    except Exception:
        pass


def cmd_run(args):
    scenarios = load_scenarios()
    scenario = find_scenario(args.id, scenarios)
    if not scenario:
        print(f"Unknown technique ID: {args.id}. Use 'list' to see available scenarios.")
        return

    check_agent_active()

    print(f"\n=== {scenario['id']} - {scenario['name']} ({scenario['tactic']}) ===")
    print(f"\nRun this on the Windows VM now:\n\n  {scenario['test_command']}\n")
    input("Press Enter once you have executed it on Windows...")

    start_time = datetime.now(timezone.utc)
    print(f"Start time recorded: {start_time.isoformat()}")
    wait = args.wait
    print(f"Waiting {wait}s for event pipeline (Sysmon -> Agent -> Manager)...")
    time.sleep(wait)

    result = correlate(scenario["id"], start_time, window_seconds=args.window)
    status, level, desc, delta = record_result(scenario, result)
    if status == "DETECTED":
        print(f"\nDETECTED - level {level} - \"{desc}\" (+{delta:.1f}s)")
    else:
        print(f"\nMISSED - no matching alert found within {args.window}s window")


def cmd_run_all(args):
    """Fully automated: execute every scenario on Windows via WinRM, no human in the loop."""
    if not HAS_WINRM:
        print("The 'pywinrm' package is not installed. Run: pip install pywinrm --break-system-packages")
        return

    scenarios = load_scenarios()
    check_agent_active()

    print(f"\nRunning {len(scenarios)} scenarios fully automated via WinRM -> {winrm_client.WINDOWS_HOST}\n")
    results_summary = []

    for scenario in scenarios:
        print(f"[{scenario['id']}] {scenario['name']} ({scenario['tactic']})")
        start_time = datetime.now(timezone.utc)
        try:
            code, out, err = winrm_client.execute_remote(scenario["test_command"], timeout=args.timeout)
            if code != 0:
                print(f"  WARN: remote command exited {code}: {err.strip()[:150]}")
        except Exception as e:
            print(f"  ERROR: could not execute on Windows: {e}")
            continue

        time.sleep(args.wait)
        result = correlate(scenario["id"], start_time, window_seconds=args.window)
        status, level, desc, delta = record_result(scenario, result)

        if status == "DETECTED":
            print(f"  -> DETECTED (level {level}, +{delta:.1f}s) {desc}")
        else:
            print(f"  -> MISSED")
        results_summary.append((scenario["id"], status))

    detected = sum(1 for _, s in results_summary if s == "DETECTED")
    total = len(results_summary)
    print(f"\nRun complete: {detected}/{total} detected ({detected/total*100:.0f}%)" if total else "\nNo scenarios ran.")
    print("Run 'python3 purpleops.py coverage' for the deduplicated report.\n")


def cmd_monitor(args):
    """Detection canary: re-run every scenario via WinRM and diff the result against the
    last saved baseline. Meant to run on a cron schedule so a detection that silently breaks
    (a changed rule, a reconfigured agent, a rebuilt VM) gets caught automatically instead of
    discovered by accident. Exits 1 if any technique regressed from DETECTED to something worse,
    so cron's mail-on-nonzero-exit (or any wrapper script) can alert on it."""
    if not HAS_WINRM:
        print("The 'pywinrm' package is not installed. Run: pip install pywinrm --break-system-packages")
        sys.exit(2)

    scenarios = load_scenarios()
    check_agent_active()

    baseline = {}
    if BASELINE_PATH.exists():
        with open(BASELINE_PATH) as f:
            baseline = json.load(f)

    run_start = datetime.now(timezone.utc)
    print(f"[{run_start.isoformat()}] PurpleOps monitor run starting ({len(scenarios)} scenarios)")

    current = {}
    for scenario in scenarios:
        start_time = datetime.now(timezone.utc)
        try:
            code, out, err = winrm_client.execute_remote(scenario["test_command"], timeout=args.timeout)
        except Exception as e:
            print(f"  [{scenario['id']}] ERROR: could not execute on Windows: {e}")
            current[scenario["id"]] = "ERROR"
            continue

        time.sleep(args.wait)
        result = correlate(scenario["id"], start_time, window_seconds=args.window)
        status, level, desc, delta = record_result(scenario, result)
        current[scenario["id"]] = status

    detected = sum(1 for s in current.values() if s == "DETECTED")
    total = len(current)
    rate = (detected / total * 100) if total else 0
    print(f"Current detection rate: {detected}/{total} ({rate:.0f}%)")

    regressions = []
    improvements = []
    for tid, status in current.items():
        prev = baseline.get(tid)
        if prev == "DETECTED" and status != "DETECTED":
            regressions.append((tid, prev, status))
        elif prev is not None and prev != "DETECTED" and status == "DETECTED":
            improvements.append((tid, prev, status))

    with open(BASELINE_PATH, "w") as f:
        json.dump(current, f, indent=2)

    if improvements:
        print("\nImprovements since last baseline:")
        for tid, prev, now in improvements:
            print(f"  {tid}: was {prev}, now {now}")

    if regressions:
        print("\n!!! DETECTION REGRESSION DETECTED !!!")
        for tid, prev, now in regressions:
            print(f"  {tid}: was {prev}, now {now}")
        print(f"\nBaseline updated at {BASELINE_PATH}. Investigate the regressed technique(s) above.")
        sys.exit(1)

    print("\nNo regressions. Baseline updated.")
    sys.exit(0)


def cmd_triage(args):
    """AI-assisted gap triage: re-run one scenario via WinRM, and if it misses, pull the raw
    telemetry from that time window and ask the configured LLM to diagnose whether it's a
    telemetry gap (nothing logged) or a rule gap (logged but unmatched) -- and draft a
    candidate Wazuh rule if it's the latter. This automates the same root-cause process used
    to find the original T1083/T1518.001/T1046 telemetry gaps by hand."""
    if not HAS_WINRM:
        print("The 'pywinrm' package is not installed. Run: pip install pywinrm --break-system-packages")
        return
    if not HAS_AI:
        print("The 'ai_triage' module failed to import. Check that its dependencies "
              "(google-generativeai or anthropic) are installed.")
        return

    scenarios = load_scenarios()
    scenario = find_scenario(args.id, scenarios)
    if not scenario:
        print(f"Unknown technique ID: {args.id}. Use 'list' to see available scenarios.")
        return

    check_agent_active()

    print(f"\n=== Triaging {scenario['id']} - {scenario['name']} ({scenario['tactic']}) ===")
    start_time = datetime.now(timezone.utc)
    try:
        code, out, err = winrm_client.execute_remote(scenario["test_command"], timeout=args.timeout)
    except Exception as e:
        print(f"ERROR: could not execute on Windows: {e}")
        return

    time.sleep(args.wait)
    result = correlate(scenario["id"], start_time, window_seconds=args.window)
    status, level, desc, delta = record_result(scenario, result)

    if status == "DETECTED":
        print(f"DETECTED - level {level} - \"{desc}\" (+{delta:.1f}s) - no triage needed.")
        return

    print("MISSED - gathering raw telemetry and asking the AI to diagnose...\n")
    raw_events = fetch_raw_events(AGENT_NAME, start_time, window_seconds=args.window)
    print(f"(found {len(raw_events)} raw archive event(s) in the correlation window)\n")

    try:
        analysis = ai_triage.triage_gap(scenario, raw_events)
    except Exception as e:
        print(f"AI triage failed: {e}")
        return

    print(analysis)

    out_dir = Path(__file__).parent / "triage_reports"
    out_dir.mkdir(exist_ok=True)
    out_path = out_dir / f"{scenario['id']}.md"
    with open(out_path, "w") as f:
        f.write(f"# Triage: {scenario['id']} - {scenario['name']}\n\n{analysis}\n")
    print(f"\nSaved to {out_path}")


def cmd_record(args):
    scenarios = load_scenarios()
    scenario = find_scenario(args.id, scenarios)
    name = scenario["name"] if scenario else args.name
    tactic = scenario["tactic"] if scenario else args.tactic

    conn = init_db()
    conn.execute(
        "INSERT INTO results (technique_id, technique_name, tactic, start_time, end_time, "
        "status, severity_level, alert_description, note) VALUES (?,?,?,?,?,?,?,?,?)",
        (args.id, name, tactic, datetime.now(timezone.utc).isoformat(),
         datetime.now(timezone.utc).isoformat(), args.status.upper(),
         args.level, args.description, args.note)
    )
    conn.commit()
    conn.close()
    print(f"Recorded {args.id} as {args.status.upper()}")


def cmd_report(args):
    conn = init_db()
    rows = conn.execute(
        "SELECT technique_id, technique_name, tactic, status, detection_time_sec, "
        "severity_level, note FROM results ORDER BY id"
    ).fetchall()
    conn.close()

    if not rows:
        print("No results recorded yet. Use 'run' or 'record' first.")
        return

    print(f"\n{'ID':<12}{'Tactic':<14}{'Name':<32}{'Status':<12}{'Latency':<10}{'Level'}")
    print("-" * 95)
    detected = 0
    for r in rows:
        tid, name, tactic, status, latency, level, note = r
        lat_str = f"{latency:.1f}s" if latency is not None else "-"
        lvl_str = str(level) if level is not None else "-"
        icon = "OK " if status == "DETECTED" else ("PART" if status == "PARTIAL" else "MISS")
        print(f"{tid:<12}{tactic:<14}{name[:30]:<32}[{icon}] {status:<9}{lat_str:<10}{lvl_str}")
        if status == "DETECTED":
            detected += 1

    total = len(rows)
    rate = (detected / total * 100) if total else 0
    print("-" * 95)
    print(f"Detection Rate: {detected}/{total} ({rate:.1f}%)\n")

    tactics = {}
    for r in rows:
        _, _, tactic, status, *_ = r
        tactics.setdefault(tactic, {"total": 0, "detected": 0})
        tactics[tactic]["total"] += 1
        if status == "DETECTED":
            tactics[tactic]["detected"] += 1

    print("Coverage by Tactic:")
    for tactic, stats in tactics.items():
        pct = stats["detected"] / stats["total"] * 100
        bar_len = int(pct / 10)
        bar = "#" * bar_len + "." * (10 - bar_len)
        print(f"  {tactic:<20}{bar} {stats['detected']}/{stats['total']} ({pct:.0f}%)")
    print()


def cmd_coverage(args):
    """Deduplicated view: best result per technique. Source of truth for gap analysis."""
    conn = init_db()
    rows = conn.execute(
        "SELECT technique_id, technique_name, tactic, status, detection_time_sec, severity_level FROM results"
    ).fetchall()
    conn.close()

    if not rows:
        print("No results recorded yet.")
        return

    rank = {"DETECTED": 2, "PARTIAL": 1, "MISSED": 0}
    best = {}
    for tid, name, tactic, status, latency, level in rows:
        cur = best.get(tid)
        if cur is None or rank[status] > rank[cur["status"]]:
            best[tid] = {"name": name, "tactic": tactic, "status": status,
                         "latency": latency, "level": level}

    print(f"\n{'ID':<12}{'Tactic':<14}{'Name':<32}{'Status':<10}{'Level'}")
    print("-" * 80)
    detected, gaps = 0, []
    for tid, d in sorted(best.items()):
        icon = "OK " if d["status"] == "DETECTED" else ("PART" if d["status"] == "PARTIAL" else "MISS")
        lvl = str(d["level"]) if d["level"] is not None else "-"
        print(f"{tid:<12}{d['tactic']:<14}{d['name'][:30]:<32}[{icon}] {d['status']:<7}{lvl}")
        if d["status"] == "DETECTED":
            detected += 1
        elif d["status"] == "MISSED":
            gaps.append((tid, d["name"], d["tactic"]))

    total = len(best)
    print("-" * 80)
    print(f"Unique Detection Rate: {detected}/{total} ({detected/total*100:.1f}%)\n")

    if gaps:
        print("=== DETECTION GAPS (require new/tuned rules) ===")
        for tid, name, tactic in gaps:
            print(f"  {tid:<12}{tactic:<14}{name}")
    print()


def cmd_export_navigator(args):
    """Export results as a MITRE ATT&CK Navigator layer JSON file."""
    conn = init_db()
    rows = conn.execute(
        "SELECT technique_id, technique_name, tactic, status, severity_level FROM results"
    ).fetchall()
    conn.close()

    if not rows:
        print("No results recorded yet.")
        return

    COLOR_DETECTED, COLOR_PARTIAL, COLOR_MISSED = "#4fb286", "#e8a23d", "#e2626b"
    rank = {"DETECTED": 2, "PARTIAL": 1, "MISSED": 0}
    best = {}
    for tid, name, tactic, status, level in rows:
        cur = best.get(tid)
        if cur is None or rank[status] > rank[cur["status"]]:
            best[tid] = {"name": name, "tactic": tactic, "status": status, "level": level}

    techniques = []
    for tid, d in best.items():
        if d["status"] == "DETECTED":
            color, score = COLOR_DETECTED, 1
        elif d["status"] == "PARTIAL":
            color, score = COLOR_PARTIAL, 0.5
        else:
            color, score = COLOR_MISSED, 0
        comment = d["status"]
        if d["level"] is not None:
            comment += f" (Wazuh rule level {d['level']})"
        techniques.append({
            "techniqueID": tid, "color": color, "score": score,
            "comment": comment, "enabled": True, "metadata": [],
            "showSubtechniques": False
        })

    layer = {
        "name": "PurpleOps Detection Coverage",
        "versions": {"attack": "14", "navigator": "4.9.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"PurpleOps detection validation results, generated {datetime.now(timezone.utc).strftime('%Y-%m-%d')}",
        "sorting": 0,
        "layout": {"layout": "side", "showAggregateScores": True, "countUnscored": False},
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {"colors": [COLOR_MISSED, COLOR_DETECTED], "minValue": 0, "maxValue": 1},
        "legendItems": [
            {"label": "Detected", "color": COLOR_DETECTED},
            {"label": "Partial", "color": COLOR_PARTIAL},
            {"label": "Gap / Missed", "color": COLOR_MISSED},
        ],
        "metadata": [],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }

    out_path = Path(__file__).parent / "navigator_layer.json"
    with open(out_path, "w") as f:
        json.dump(layer, f, indent=2)
    print(f"Navigator layer written to {out_path}")
    print("Upload it at https://mitre-attack.github.io/attack-navigator/ (Open Existing Layer -> Upload)")


def main():
    parser = argparse.ArgumentParser(description="PurpleOps Detection Validation Engine")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list", help="List available ATT&CK test scenarios").set_defaults(func=cmd_list)
    sub.add_parser("agents", help="Show live agent status via Wazuh API").set_defaults(func=cmd_agents)

    p_run = sub.add_parser("run", help="Run a single test (manual execution) and auto-correlate")
    p_run.add_argument("id", help="Technique ID, e.g. T1059.001")
    p_run.add_argument("--wait", type=int, default=15, help="Seconds to wait before checking alerts")
    p_run.add_argument("--window", type=int, default=90, help="Correlation window in seconds")
    p_run.set_defaults(func=cmd_run)

    p_run_all = sub.add_parser("run-all", help="Fully automated: execute ALL scenarios on Windows via WinRM")
    p_run_all.add_argument("--wait", type=int, default=15, help="Seconds to wait before checking alerts")
    p_run_all.add_argument("--window", type=int, default=90, help="Correlation window in seconds")
    p_run_all.add_argument("--timeout", type=int, default=30, help="WinRM command timeout in seconds")
    p_run_all.set_defaults(func=cmd_run_all)

    p_monitor = sub.add_parser("monitor", help="Detection canary: re-run all scenarios, diff vs last baseline, exit 1 on regression")
    p_monitor.add_argument("--wait", type=int, default=15, help="Seconds to wait before checking alerts")
    p_monitor.add_argument("--window", type=int, default=90, help="Correlation window in seconds")
    p_monitor.add_argument("--timeout", type=int, default=30, help="WinRM command timeout in seconds")
    p_monitor.set_defaults(func=cmd_monitor)

    p_triage = sub.add_parser("triage", help="AI-assisted gap triage: re-run one scenario and have the AI diagnose a MISS")
    p_triage.add_argument("id", help="Technique ID, e.g. T1059.001")
    p_triage.add_argument("--wait", type=int, default=15, help="Seconds to wait before checking alerts")
    p_triage.add_argument("--window", type=int, default=90, help="Correlation window in seconds")
    p_triage.add_argument("--timeout", type=int, default=30, help="WinRM command timeout in seconds")
    p_triage.set_defaults(func=cmd_triage)

    p_rec = sub.add_parser("record", help="Manually record a result (backfill)")
    p_rec.add_argument("id", help="Technique ID")
    p_rec.add_argument("--status", required=True, choices=["DETECTED", "MISSED", "PARTIAL"])
    p_rec.add_argument("--name", default="", help="Technique name (if not in scenarios.json)")
    p_rec.add_argument("--tactic", default="", help="Tactic (if not in scenarios.json)")
    p_rec.add_argument("--level", type=int, default=None, help="Alert severity level")
    p_rec.add_argument("--description", default=None, help="Alert description")
    p_rec.add_argument("--note", default=None, help="Free-text note")
    p_rec.set_defaults(func=cmd_record)

    sub.add_parser("report", help="Show detection rate report (raw, includes duplicates)").set_defaults(func=cmd_report)
    sub.add_parser("coverage", help="Deduplicated gap analysis (best result per technique)").set_defaults(func=cmd_coverage)
    sub.add_parser("export-navigator", help="Export MITRE ATT&CK Navigator layer JSON").set_defaults(func=cmd_export_navigator)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
