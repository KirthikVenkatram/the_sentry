"""
Sentry Defense Grid — Live Fire Exercise
=========================================
Simulates all 4 severity levels (LOW/MEDIUM/HIGH/CRITICAL) for all 6 scenarios.
Each scenario fires 4 variants so every Slack card type appears in the demo.

Usage:
  python3 simulation/gen_attack_campaign.py              # all scenarios, all severities
  python3 simulation/gen_attack_campaign.py --scenario 1 # one scenario, all 4 severities
  python3 simulation/gen_attack_campaign.py --list       # list scenarios
"""

import random
import os
import argparse
from datetime import datetime, timedelta, timezone
from elasticsearch import Elasticsearch, helpers
from dotenv import load_dotenv

load_dotenv()

ELASTIC_URL     = os.getenv("ELASTIC_URL", "")
ELASTIC_API_KEY = os.getenv("ELASTIC_API_KEY", "")

AUTH_INDEX = "sentry-auth-logs"
NET_INDEX  = "sentry-network-logs"

# ── Helpers ───────────────────────────────────────────────────────────────────

def ts(offset_minutes=0):
    """UTC timestamp, optionally offset into the past."""
    t = datetime.now(timezone.utc) - timedelta(minutes=offset_minutes)
    return t.isoformat().replace("+00:00", "Z")

def auth_doc(source_doc):
    return {"_index": AUTH_INDEX, "_op_type": "create", "_source": source_doc}

def net_doc(source_doc):
    return {"_index": NET_INDEX, "_op_type": "create", "_source": source_doc}

# ── Connection ────────────────────────────────────────────────────────────────

def connect_to_elastic():
    print("🔌 Connecting to Elastic Serverless...")
    try:
        client = Elasticsearch(hosts=[ELASTIC_URL], api_key=ELASTIC_API_KEY)
        if client.ping():
            print(f"✅ Connected: {client.info()['cluster_name']}")
            return client
        print("❌ Connection failed.")
    except Exception as e:
        print(f"❌ Error: {e}")
    return None

# ── Scenario 1: Brute Force ───────────────────────────────────────────────────
# LOW:      75 attempts  — Germany      → auto disable
# MEDIUM:   150 attempts — France       → auto disable + war room
# HIGH:     300 attempts — Russia       → approval required
# CRITICAL: 600 attempts — Sudan        → approval required

def scenario_1_brute_force(actions):
    print("\n🔥 SCENARIO 1: Brute Force Attack (4 severity levels)")

    variants = [
        {"count": 75,  "ip": "1.1.1.10",     "user": "jdoe",    "country": "Germany", "label": "LOW"},
        {"count": 150, "ip": "2.2.2.20",     "user": "msmith",  "country": "France",  "label": "MEDIUM"},
        {"count": 300, "ip": "45.33.100.1",  "user": "svc_acct","country": "Russia",  "label": "HIGH"},
        {"count": 600, "ip": "203.0.113.42", "user": "admin",   "country": "Sudan",   "label": "CRITICAL"},
    ]

    for v in variants:
        for _ in range(v["count"]):
            actions.append(auth_doc({
                "@timestamp": ts(),
                "event":      {"category": "authentication", "outcome": "failure"},
                "source":     {"ip": v["ip"], "geo": {"country_name": v["country"]}},
                "user":       {"name": v["user"]},
                "error":      {"message": "Invalid password"},
                "host":       {"name": "auth-server-01"},
                "scenario":   "BRUTE_FORCE",
                "tags":       ["security_incident", "brute_force"],
            }))
        print(f"   ↳ [{v['label']}] {v['count']} attempts from {v['ip']} ({v['country']}) → {v['user']}")

# ── Scenario 2: Impossible Travel ─────────────────────────────────────────────
# MEDIUM:   US → France        (unusual but not high-risk)
# HIGH:     US → Russia        (high-risk country)
# HIGH:     US → Iran          (high-risk country)
# CRITICAL: US → North Korea   (high-risk + active session)

def scenario_2_impossible_travel(actions):
    print("\n🔥 SCENARIO 2: Impossible Travel (4 severity levels)")

    variants = [
        {"user": "alice.wong",   "src_country": "United States", "src_ip": "192.168.1.10",  "dst_country": "France",       "dst_ip": "80.12.45.67",   "label": "MEDIUM"},
        {"user": "bob.jones",    "src_country": "United States", "src_ip": "192.168.1.20",  "dst_country": "Russia",       "dst_ip": "95.173.130.1",  "label": "HIGH"},
        {"user": "carol.nguyen", "src_country": "United States", "src_ip": "192.168.1.30",  "dst_country": "Iran",         "dst_ip": "5.200.14.128",  "label": "HIGH"},
        {"user": "john.smith",   "src_country": "United States", "src_ip": "192.168.1.100", "dst_country": "North Korea",  "dst_ip": "175.45.176.1",  "label": "CRITICAL"},
    ]

    now = datetime.now(timezone.utc)
    for v in variants:
        # Legit login 10 min ago
        actions.append(auth_doc({
            "@timestamp": (now - timedelta(minutes=10)).isoformat().replace("+00:00", "Z"),
            "event":  {"category": "authentication", "outcome": "success"},
            "source": {"ip": v["src_ip"], "geo": {"country_name": v["src_country"]}},
            "user":   {"name": v["user"]},
            "host":   {"name": "vpn-gateway-01"},
            "scenario": "IMPOSSIBLE_TRAVEL",
            "tags":   ["security_incident", "impossible_travel"],
        }))
        # Suspicious foreign login now
        actions.append(auth_doc({
            "@timestamp": now.isoformat().replace("+00:00", "Z"),
            "event":  {"category": "authentication", "outcome": "success"},
            "source": {"ip": v["dst_ip"], "geo": {"country_name": v["dst_country"]}},
            "user":   {"name": v["user"]},
            "host":   {"name": "vpn-gateway-01"},
            "scenario": "IMPOSSIBLE_TRAVEL",
            "tags":   ["security_incident", "impossible_travel"],
        }))
        print(f"   ↳ [{v['label']}] {v['user']}: US → {v['dst_country']}")

# ── Scenario 3: Data Exfiltration ─────────────────────────────────────────────
# LOW:      200MB → Germany    (non-sanctioned)
# MEDIUM:   700MB → Germany    (non-sanctioned)
# HIGH:     3GB   → Germany    (non-sanctioned but large)
# CRITICAL: 6GB   → Iran       (sanctioned country)

def scenario_3_data_exfiltration(actions):
    print("\n🔥 SCENARIO 3: Data Exfiltration (4 severity levels)")

    variants = [
        {"src": "10.0.1.1", "dst": "8.8.4.4",          "country": "Germany", "chunks": 2,  "bytes_each": 100_000_000, "label": "LOW"},
        {"src": "10.0.1.2", "dst": "31.13.72.36",       "country": "Germany", "chunks": 7,  "bytes_each": 100_000_000, "label": "MEDIUM"},
        {"src": "10.0.1.3", "dst": "104.21.45.67",      "country": "Germany", "chunks": 30, "bytes_each": 100_000_000, "label": "HIGH"},
        {"src": "10.0.0.5", "dst": "185.220.101.5",     "country": "Iran",    "chunks": 60, "bytes_each": 100_000_000, "label": "CRITICAL"},
    ]

    for v in variants:
        for _ in range(v["chunks"]):
            actions.append(net_doc({
                "@timestamp":  ts(),
                "event":       {"category": "network", "type": "flow", "action": "allow"},
                "source":      {"ip": v["src"]},
                "destination": {"ip": v["dst"], "port": 443,
                                "geo": {"country_name": v["country"]}},
                "network":     {"bytes": random.randint(v["bytes_each"], v["bytes_each"] + 10_000_000)},
                "scenario":    "DATA_EXFILTRATION",
                "tags":        ["security_incident", "exfiltration"],
            }))
        total_gb = round(v["chunks"] * v["bytes_each"] / 1e9, 1)
        print(f"   ↳ [{v['label']}] {v['src']} → {v['dst']} ({v['country']}) ~{total_gb}GB")

# ── Scenario 4: Port Scan ─────────────────────────────────────────────────────
# LOW:      30 ports   → auto block
# MEDIUM:   75 ports   → auto block + war room
# HIGH:     150 ports  → approval required
# CRITICAL: 250 ports  → approval required

def scenario_4_port_scan(actions):
    print("\n🔥 SCENARIO 4: Port Scan (4 severity levels)")

    variants = [
        {"ip": "10.20.30.1",  "country": "China",   "ports": 30,  "label": "LOW"},
        {"ip": "10.20.30.2",  "country": "China",   "ports": 75,  "label": "MEDIUM"},
        {"ip": "45.33.22.11", "country": "Russia",  "ports": 150, "label": "HIGH"},
        {"ip": "91.108.4.1",  "country": "Belarus", "ports": 250, "label": "CRITICAL"},
    ]

    for v in variants:
        ports = random.sample(range(1, 65535), v["ports"])
        for port in ports:
            actions.append(net_doc({
                "@timestamp":  ts(),
                "event":       {"category": "network", "type": "connection", "action": "denied"},
                "source":      {"ip": v["ip"], "geo": {"country_name": v["country"]}},
                "destination": {"ip": "10.0.0.1", "port": port},
                "network":     {"bytes": 64},
                "scenario":    "PORT_SCAN",
                "tags":        ["security_incident", "port_scan"],
            }))
        print(f"   ↳ [{v['label']}] {v['ip']} ({v['country']}) scanned {v['ports']} ports")

# ── Scenario 5: Lateral Movement ──────────────────────────────────────────────
# LOW:      3 hosts  → monitor
# MEDIUM:   8 hosts  → isolate
# HIGH:     15 hosts → approval required
# CRITICAL: 25 hosts → approval required

def scenario_5_lateral_movement(actions):
    print("\n🔥 SCENARIO 5: Lateral Movement (4 severity levels)")

    variants = [
        {"src": "10.0.1.50", "host_count": 3,  "label": "LOW"},
        {"src": "10.0.1.51", "host_count": 8,  "label": "MEDIUM"},
        {"src": "10.0.0.22", "host_count": 15, "label": "HIGH"},
        {"src": "10.0.0.23", "host_count": 25, "label": "CRITICAL"},
    ]

    for v in variants:
        targets = [f"10.0.{random.randint(0,5)}.{random.randint(1,254)}"
                   for _ in range(v["host_count"])]
        for target in targets:
            for port in [22, 445, 3389]:
                actions.append(net_doc({
                    "@timestamp":  ts(),
                    "event":       {"category": "network", "type": "connection", "action": "allow"},
                    "source":      {"ip": v["src"]},
                    "destination": {"ip": target, "port": port},
                    "network":     {"bytes": random.randint(1000, 50000)},
                    "scenario":    "LATERAL_MOVEMENT",
                    "tags":        ["security_incident", "lateral_movement"],
                }))
        print(f"   ↳ [{v['label']}] {v['src']} moved to {v['host_count']} hosts")

# ── Scenario 6: Privilege Escalation ──────────────────────────────────────────
# MEDIUM:   4 attempts  → auto disable
# MEDIUM:   5 attempts  → auto disable
# HIGH:     8 attempts  → approval required
# HIGH:     15 attempts → approval required

def scenario_6_privilege_escalation(actions):
    print("\n🔥 SCENARIO 6: Privilege Escalation (4 severity levels)")

    admin_routes = [
        "/admin/users", "/admin/config", "/api/v1/admin/reset",
        "/admin/roles", "/admin/audit-logs",
    ]

    variants = [
        {"user": "intern.kim",   "ip": "10.0.2.10", "attempts": 4,  "label": "MEDIUM"},
        {"user": "contractor.j", "ip": "10.0.2.11", "attempts": 5,  "label": "MEDIUM"},
        {"user": "dev.patel",    "ip": "10.0.2.12", "attempts": 8,  "label": "HIGH"},
        {"user": "bob.jones",    "ip": "10.0.0.45", "attempts": 15, "label": "HIGH"},
    ]

    for v in variants:
        routes = random.choices(admin_routes, k=v["attempts"])
        for route in routes:
            actions.append(auth_doc({
                "@timestamp": ts(),
                "event":      {"category": "authentication", "outcome": "failure", "type": "access"},
                "source":     {"ip": v["ip"]},
                "user":       {"name": v["user"], "roles": ["standard"]},
                "url":        {"path": route},
                "http":       {"response": {"status_code": 403}},
                "scenario":   "PRIVILEGE_ESCALATION",
                "tags":       ["security_incident", "privilege_escalation"],
            }))
        print(f"   ↳ [{v['label']}] {v['user']} hit {v['attempts']} admin endpoints from {v['ip']}")

# ── Runner ────────────────────────────────────────────────────────────────────

SCENARIOS = {
    1: scenario_1_brute_force,
    2: scenario_2_impossible_travel,
    3: scenario_3_data_exfiltration,
    4: scenario_4_port_scan,
    5: scenario_5_lateral_movement,
    6: scenario_6_privilege_escalation,
}

SCENARIO_NAMES = {
    1: "Brute Force          (LOW / MEDIUM / HIGH / CRITICAL)",
    2: "Impossible Travel    (MEDIUM / HIGH / HIGH / CRITICAL)",
    3: "Data Exfiltration    (LOW / MEDIUM / HIGH / CRITICAL)",
    4: "Port Scan            (LOW / MEDIUM / HIGH / CRITICAL)",
    5: "Lateral Movement     (LOW / MEDIUM / HIGH / CRITICAL)",
    6: "Privilege Escalation (MEDIUM / MEDIUM / HIGH / HIGH)",
}


def run_campaign(client, scenario_ids=None):
    print("\n" + "=" * 56)
    print("🚀 SENTRY LIVE FIRE EXERCISE — ALL SEVERITY LEVELS")
    print("=" * 56)

    actions = []
    ids = scenario_ids or list(SCENARIOS.keys())
    for sid in ids:
        if sid in SCENARIOS:
            SCENARIOS[sid](actions)

    total = len(actions)
    print(f"\n📤 Streaming {total} log events to Elastic Cloud...")
    try:
        success, failed = helpers.bulk(client, actions, stats_only=True)
        print(f"✅ UPLOAD COMPLETE: {success} sent, {failed} failed")
    except Exception as e:
        print(f"❌ Upload Error: {e}")

    print("\n" + "=" * 56)
    print("🎯 ATTACK CAMPAIGN COMPLETE")
    print("   Kibana alert rules will fire within 2-5 minutes.")
    print("   Watch Slack for all 4 severity card types.")
    print("=" * 56)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sentry Attack Simulator")
    parser.add_argument("--scenario", type=int, choices=list(SCENARIOS.keys()),
                        help="Run a single scenario (1-6). Omit to run all.")
    parser.add_argument("--list", action="store_true", help="List all scenarios")
    args = parser.parse_args()

    if args.list:
        print("\nAvailable scenarios:")
        for sid, name in SCENARIO_NAMES.items():
            print(f"  {sid}. {name}")
        exit(0)

    es = connect_to_elastic()
    if es:
        ids = [args.scenario] if args.scenario else None
        run_campaign(es, ids)