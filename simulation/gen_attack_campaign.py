"""
Sentry Defense Grid — Live Fire Exercise
=========================================
Simulates 6 real-world attack scenarios against your Elastic indices.

Usage:
  python3 simulation/gen_attack_campaign.py              # run all scenarios
  python3 simulation/gen_attack_campaign.py --scenario 1 # run one scenario
  python3 simulation/gen_attack_campaign.py --list       # list scenarios
"""

import random
import os
import argparse
from datetime import datetime, timedelta
from elasticsearch import Elasticsearch, helpers
from dotenv import load_dotenv

load_dotenv()

ELASTIC_URL     = os.getenv("ELASTIC_URL", "")
ELASTIC_API_KEY = os.getenv("ELASTIC_API_KEY", "")

AUTH_INDEX = "sentry-auth-logs"
NET_INDEX  = "sentry-network-logs"

# ── Helpers ───────────────────────────────────────────────────────────────────

def ts():
    from datetime import timezone
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

def auth_doc(source_doc):
    """Wrap auth log doc for data stream bulk insert."""
    return {"_index": AUTH_INDEX, "_op_type": "create", "_source": source_doc}

def net_doc(source_doc):
    """Wrap network log doc for data stream bulk insert."""
    return {"_index": NET_INDEX, "_op_type": "create", "_source": source_doc}

# ── Connection ────────────────────────────────────────────────────────────────

def connect_to_elastic():
    print("🔌 Connecting to Elastic Serverless...")
    try:
        client = Elasticsearch(hosts=[ELASTIC_URL], api_key=ELASTIC_API_KEY)
        if client.ping():
            print(f"✅ Connected: {client.info()['cluster_name']}")
            return client
        print("❌ Connection failed. Check ELASTIC_URL and ELASTIC_API_KEY in .env")
    except Exception as e:
        print(f"❌ Error: {e}")
    return None

# ── Scenario Generators ───────────────────────────────────────────────────────

def scenario_1_brute_force(actions):
    print("\n🔥 SCENARIO 1: Brute Force Attack (HIGH severity)")
    for _ in range(300):
        actions.append(auth_doc({
            "@timestamp": ts(),
            "event":      {"category": "authentication", "outcome": "failure"},
            "source":     {"ip": "203.0.113.42", "geo": {"country_name": "Sudan"}},
            "user":       {"name": "admin"},
            "error":      {"message": "Invalid password"},
            "host":       {"name": "auth-server-01"},
            "scenario":   "BRUTE_FORCE",
            "tags":       ["security_incident", "brute_force"],
        }))
    print("   ↳ 300 failed logins from 203.0.113.42 (Sudan) targeting 'admin'")


def scenario_2_impossible_travel(actions):
    print("\n🔥 SCENARIO 2: Impossible Travel (MEDIUM severity)")
    now = datetime.utcnow()
    actions.append(auth_doc({
        "@timestamp": (now - timedelta(minutes=10)).isoformat() + "Z",
        "event":      {"category": "authentication", "outcome": "success"},
        "source":     {"ip": "192.168.1.100", "geo": {"country_name": "United States"}},
        "user":       {"name": "john.smith"},
        "host":       {"name": "vpn-gateway-01"},
        "scenario":   "IMPOSSIBLE_TRAVEL",
        "tags":       ["security_incident", "impossible_travel"],
    }))
    actions.append(auth_doc({
        "@timestamp": now.isoformat() + "Z",
        "event":      {"category": "authentication", "outcome": "success"},
        "source":     {"ip": "197.157.2.50", "geo": {"country_name": "Sudan"}},
        "user":       {"name": "john.smith"},
        "host":       {"name": "vpn-gateway-01"},
        "scenario":   "IMPOSSIBLE_TRAVEL",
        "tags":       ["security_incident", "impossible_travel"],
    }))
    print("   ↳ 'john.smith' logged in from US then Sudan within 10 minutes")


def scenario_3_data_exfiltration(actions):
    print("\n🔥 SCENARIO 3: Data Exfiltration (CRITICAL severity)")
    for _ in range(60):
        actions.append(net_doc({
            "@timestamp":  ts(),
            "event":       {"category": "network", "type": "flow", "action": "allow"},
            "source":      {"ip": "10.0.0.5"},
            "destination": {"ip": "185.220.101.5", "port": 443,
                            "geo": {"country_name": "Iran"}},
            "network":     {"bytes": random.randint(100_000_000, 110_000_000)},
            "threat":      {"indicator": "high_volume_upload"},
            "scenario":    "DATA_EXFILTRATION",
            "tags":        ["security_incident", "exfiltration"],
        }))
    print("   ↳ 10.0.0.5 sending ~6GB to 185.220.101.5 (Iran)")


def scenario_4_port_scan(actions):
    print("\n🔥 SCENARIO 4: Port Scan (HIGH severity)")
    ports = random.sample(range(1, 65535), 150)
    for port in ports:
        actions.append(net_doc({
            "@timestamp":  ts(),
            "event":       {"category": "network", "type": "connection",
                            "action": "denied"},
            "source":      {"ip": "45.33.22.11", "geo": {"country_name": "Russia"}},
            "destination": {"ip": "10.0.0.1", "port": port},
            "network":     {"bytes": 64},
            "scenario":    "PORT_SCAN",
            "tags":        ["security_incident", "port_scan"],
        }))
    print(f"   ↳ 45.33.22.11 scanned {len(ports)} ports on 10.0.0.1")


def scenario_5_lateral_movement(actions):
    print("\n🔥 SCENARIO 5: Lateral Movement (HIGH severity)")
    internal_ips = [f"10.0.0.{i}" for i in range(1, 16)]
    for target in internal_ips:
        for port in [22, 445, 3389]:
            actions.append(net_doc({
                "@timestamp":  ts(),
                "event":       {"category": "network", "type": "connection",
                                "action": "allow"},
                "source":      {"ip": "10.0.0.22"},
                "destination": {"ip": target, "port": port},
                "network":     {"bytes": random.randint(1000, 50000)},
                "scenario":    "LATERAL_MOVEMENT",
                "tags":        ["security_incident", "lateral_movement"],
            }))
    print(f"   ↳ 10.0.0.22 moved laterally to {len(internal_ips)} hosts via SSH/SMB/RDP")


def scenario_6_privilege_escalation(actions):
    print("\n🔥 SCENARIO 6: Privilege Escalation (HIGH severity)")
    admin_routes = [
        "/admin/users", "/admin/config", "/api/v1/admin/reset",
        "/admin/roles", "/admin/audit-logs",
    ]
    for route in admin_routes:
        for _ in range(3):
            actions.append(auth_doc({
                "@timestamp": ts(),
                "event":      {"category": "authentication", "outcome": "failure",
                               "type": "access"},
                "source":     {"ip": "10.0.0.45"},
                "user":       {"name": "bob.jones", "roles": ["standard"]},
                "url":        {"path": route},
                "http":       {"response": {"status_code": 403}},
                "scenario":   "PRIVILEGE_ESCALATION",
                "tags":       ["security_incident", "privilege_escalation"],
            }))
    print(f"   ↳ 'bob.jones' attempted {len(admin_routes)} admin endpoints × 3 = "
          f"{len(admin_routes) * 3} 403 errors")


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
    1: "Brute Force",
    2: "Impossible Travel",
    3: "Data Exfiltration",
    4: "Port Scan",
    5: "Lateral Movement",
    6: "Privilege Escalation",
}


def run_campaign(client, scenario_ids=None):
    print("\n" + "=" * 50)
    print("🚀 SENTRY LIVE FIRE EXERCISE")
    print("=" * 50)

    actions = []
    ids = scenario_ids or list(SCENARIOS.keys())
    for sid in ids:
        if sid in SCENARIOS:
            SCENARIOS[sid](actions)

    print(f"\n📤 Streaming {len(actions)} log events to Elastic Cloud...")
    try:
        success, failed = helpers.bulk(client, actions, stats_only=True)
        print(f"✅ UPLOAD COMPLETE: {success} sent, {failed} failed")
    except Exception as e:
        print(f"❌ Upload Error: {e}")

    print("\n" + "=" * 50)
    print("🎯 ATTACK CAMPAIGN COMPLETE")
    print("   Kibana alert rules will fire within 5 minutes.")
    print("   Watch your server terminal for incoming webhooks.")
    print("=" * 50)


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