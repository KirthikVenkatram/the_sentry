<div align="center">

# 🛡️ The Sentry

### Autonomous AI-Powered Security Operations Platform

[![Elastic](https://img.shields.io/badge/Elastic-Cloud-005571?style=for-the-badge&logo=elasticsearch&logoColor=white)](https://elastic.co)
[![Python](https://img.shields.io/badge/Python-3.13-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Slack](https://img.shields.io/badge/Slack-Integration-4A154B?style=for-the-badge&logo=slack&logoColor=white)](https://slack.com)
[![MCP](https://img.shields.io/badge/MCP-Enabled-FF6B35?style=for-the-badge)](https://modelcontextprotocol.io)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

*Detect. Score. Respond. Autonomously.*

</div>

---

## 📖 Overview

**Sentry Defense Grid** is a fully autonomous Security Operations Center (SOC) built on Elastic Cloud, powered by a multi-agent AI system using the Model Context Protocol (MCP). It detects threats in real time using ES|QL, scores severity, and either **auto-remediates low-risk threats** or **requests human approval via Slack** for high-risk actions — all without a human watching a terminal.

> Built for the **Elastic Agent Builder Hackathon 2026**

---

## ✨ Key Features

| Feature | Description |
|---|---|
| 🔍 **Real-time Detection** | 6 ES|QL detection rules running every 2–5 minutes in Kibana |
| 🧠 **AI Severity Scoring** | Custom engine scores threats LOW → CRITICAL with per-scenario thresholds |
| ⚡ **Autonomous Response** | LOW/MEDIUM threats auto-remediated with zero human intervention |
| 🛑 **Human-in-the-Loop** | HIGH/CRITICAL threats send Slack approval buttons before any destructive action |
| 🤖 **Multi-Agent AI** | 3 specialized agents (Alpha, Beta, Gamma) coordinate via shared War Room |
| 📋 **Auto Case Creation** | Every HIGH/CRITICAL incident auto-creates an Elastic Security case |
| 📨 **Slack Native** | Full approval workflow in Slack — no terminal needed for demos |
| 🔌 **MCP Integration** | Elastic Agent Builder connects to your tools via Model Context Protocol |

---

## 🏗️ Architecture

```text
+----------------------------------------------------------------------------+
|                              ELASTIC CLOUD                                 |
|                                                                            |
|  Indices:                                                                  |
|  +----------------------+      +--------------------------------------+    |
|  | sentry-auth-logs     | ---> |                                      |    |
|  | sentry-network-logs  | ---> |               KIBANA                 |    |
|  +----------------------+      |                                      |    |
|                                |  ES|QL Detection Rules                |    |
|                                |  - Brute Force (2m)                   |    |
|                                |  - Impossible Travel (5m)             |    |
|                                |  - Data Exfiltration (5m)             |    |
|                                |  - Port Scan (5m)                     |    |
|                                |  - Lateral Movement (5m)              |    |
|                                |  - Privilege Escalation (5m)          |    |
|                                +--------------------+-----------------+    |
|                                                     | Webhook POST         |
+-----------------------------------------------------+----------------------+
                                                      |
                                                      v
+----------------------------------------------------------------------------+
|                      SENTRY MCP SERVER (Python)                            |
|                                                                            |
|  POST /webhook/alert                                                       |
|                                                                            |
|  1. Receive detection from Kibana                                          |
|  2. Query Elasticsearch (ES|QL)                                            |
|  3. Score severity: LOW / MEDIUM / HIGH / CRITICAL                        |
|                                                                            |
|  LOW / MEDIUM                 HIGH / CRITICAL                              |
|  -----------------            ----------------------------                  |
|  Auto-remediation             Slack approval required                      |
|  - Disable user               [APPROVE] [DENY]                             |
|  - Block IP                   Human triggers /webhook/slack                |
|  - Isolate host               Execute if approved                          |
|                                                                            |
|  HIGH / CRITICAL: Create Elastic Case                                      |
|                                                                            |
|  MCP endpoint: /mcp (Agent Builder connects here)                          |
+----------------------------------------------------------------------------+
             |                                      |
             v                                      v
+---------------------------+        +----------------------------------+
|           SLACK           |        |      ELASTIC AGENT BUILDER      |
|      #sentry-alerts       |        |                                  |
|                           |        |  Agent Alpha  - Identity         |
|  CRITICAL Alert           |        |  Agent Beta   - Network          |
|  [APPROVE] [DENY]         |        |  Agent Gamma  - Commander        |
|                           |        |                                  |
+---------------------------+        +----------------------------------+

```

---

## 🎯 Threat Detection Scenarios

### Severity Thresholds

| Scenario | LOW (auto) | MEDIUM (auto) | HIGH (approval) | CRITICAL (approval) |
|---|---|---|---|---|
| **Brute Force** | 50–100 attempts | 100–200 | 200–500 | 500+ or high-risk country |
| **Data Exfiltration** | 100–500 MB | 500 MB–1 GB | 1–5 GB | 5 GB+ or sanctioned country |
| **Port Scan** | 20–50 ports | 50–100 ports | 100–200 ports | 200+ ports |
| **Lateral Movement** | 2–5 hosts | 5–10 hosts | 10–20 hosts | 20+ or domain controller |
| **Privilege Escalation** | — | 3–5 attempts | 5+ attempts | Admin access gained |
| **Impossible Travel** | — | Unusual country | High-risk country | Active session ongoing |

> 🌍 **High-risk countries** (Sudan, Russia, North Korea, Iran, Belarus) automatically bump severity by one level.

---

## 🤖 AI Agent Roles

### 🔵 Agent Alpha — Identity Defense
Handles all user account threats: brute force, impossible travel, privilege escalation. Runs ES|QL queries against `sentry-auth-logs`, scores severity, and either disables accounts autonomously or requests approval via War Room.

### 🟢 Agent Beta — Network Defense
Handles all network threats: data exfiltration, port scanning, lateral movement. Runs ES|QL queries against `sentry-network-logs`, blocks IPs and isolates hosts autonomously for LOW/MEDIUM.

### 🔴 Agent Gamma — SOC Commander
Reads the shared War Room, correlates multi-vector attacks, and manages the human-in-the-loop approval process. Detects when Alpha AND Beta both report threats from the same IP — escalates to CRITICAL automatically.

---

## 📁 Project Structure

```
Sentry/
├── mcp_server/
│   ├── server.py                 # Main server — MCP + webhook endpoints
│   ├── config.py                 # Environment config
│   └── tools/
│       ├── identity.py           # disable_user, AD integration
│       ├── network.py            # block_ip, isolate_host
│       ├── coordination.py       # War room, approval system
│       ├── elastic_integrations.py  # Case creation, workflows
│       └── severity.py           # Threat scoring engine
├── simulation/
│   └── gen_attack_campaign.py    # 6-scenario attack simulator
├── agents/
│   ├── agent_alpha.md            # Alpha agent instructions
│   ├── agent_beta.md             # Beta agent instructions
│   └── agent_gamma.md            # Gamma agent instructions
├── .env.example                  # Environment template
├── .gitignore
└── README.md
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- Elastic Cloud (Serverless) account
- Slack workspace with admin access
- ngrok (for local development)

### 1 — Clone & Install

```bash
git clone https://github.com/YOUR_USERNAME/sentry-defense-grid
cd sentry-defense-grid
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 2 — Configure Environment

```bash
cp .env.example .env
```

Edit `.env`:
```env
# Elastic Serverless
ELASTIC_URL=https://your-deployment.es.us-central1.gcp.elastic.cloud
ELASTIC_API_KEY=your_api_key_here

# Slack
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK
SLACK_BOT_TOKEN=xoxb-your-bot-token
SLACK_SIGNING_SECRET=your_signing_secret
SLACK_CHANNEL=#sentry-alerts
```

### 3 — Set Up Elastic Data Streams

In Kibana → Dev Tools, run:

```json
PUT _index_template/sentry-auth-logs
{
  "index_patterns": ["sentry-auth-logs"],
  "data_stream": {},
  "template": {
    "mappings": {
      "properties": {
        "@timestamp":              { "type": "date" },
        "event.outcome":           { "type": "keyword" },
        "source.ip":               { "type": "ip" },
        "source.geo.country_name": { "type": "keyword" },
        "user.name":               { "type": "keyword" }
      }
    }
  }
}

PUT _data_stream/sentry-auth-logs
PUT _data_stream/sentry-network-logs
```

### 4 — Start Server

```bash
# Terminal 1 — MCP Server
python3 mcp_server/server.py

# Terminal 2 — ngrok tunnel
ngrok http 8000
```

### 5 — Configure Kibana

1. **Webhook Connector**: Stack Management → Connectors → Webhook → URL: `https://YOUR-NGROK/webhook/alert`
2. **Alert Rules**: Create 6 ES|QL rules (see `/kibana_rules.md` for queries)
3. **MCP Connector**: Agent Builder → Tools → New MCP → URL: `https://YOUR-NGROK/mcp`
4. **Agents**: Create Alpha, Beta, Gamma using instructions in `/agents/`

### 6 — Run Attack Simulation

```bash
python3 simulation/gen_attack_campaign.py
```

Watch `#sentry-alerts` in Slack light up automatically.

---

## 🖥️ API Endpoints

| Endpoint | Method | Description |
|---|---|---|
| `/mcp` | GET/POST | MCP tool server — Elastic Agent Builder connects here |
| `/webhook/alert` | POST | Kibana detection rule webhook target |
| `/webhook/slack` | POST | Slack button interaction handler |
| `/webhook/approve` | POST | Manual approval fallback (curl) |
| `/status` | GET | Health check + War Room snapshot |

### Manual Test

```bash
# Trigger a CRITICAL brute force alert
curl -X POST https://YOUR-NGROK/webhook/alert \
  -H "Content-Type: application/json" \
  -d '{"scenario":"BRUTE_FORCE"}'

# Approve a pending action
curl -X POST https://YOUR-NGROK/webhook/approve \
  -H "Content-Type: application/json" \
  -d '{"approval_id":"XXXXXXXX","decision":"yes"}'

# Check War Room status
curl https://YOUR-NGROK/status
```

---

## 🛠️ MCP Tools Reference

| Tool | Agent | Description |
|---|---|---|
| `disable_user_account` | Alpha | Disable compromised AD account + terminate sessions |
| `block_ip_address` | Beta | Block malicious IP at perimeter firewall |
| `isolate_host` | Beta | Quarantine compromised host to VLAN 999 |
| `read_war_room_state` | Gamma | Read shared incident context |
| `post_war_room_message` | All | Broadcast finding to War Room |
| `request_human_approval` | Gamma | Trigger Slack approval workflow |
| `create_case` | Gamma | Create Elastic Security case |
| `trigger_workflow` | Gamma | Fire automated remediation workflow |

---

## 🎬 Demo Flow

> **No terminal needed except for the attack simulation**

1. Open `#sentry-alerts` in Slack
2. Open Kibana Agent Builder → Agent Gamma chat
3. Run the attack simulation:
   ```bash
   python3 simulation/gen_attack_campaign.py
   ```
4. Watch Slack receive 6 automatic alerts
5. LOW/MEDIUM threats show green ✅ auto-resolved notifications
6. HIGH/CRITICAL threats show red 🛑 approval requests with buttons
7. Click **✅ APPROVE** on one — watch Slack confirm execution
8. Click **❌ DENY** on another — watch it log as human-denied
9. In Kibana → Stack Management → Cases — all incidents documented
10. In Agent Gamma chat: *"Read the war room and give me a full incident briefing"*

---

## 🔐 Security Notes

- `.env` is gitignored — never commit secrets
- Slack request signatures verified via HMAC-SHA256
- Approval IDs are cryptographically random UUIDs
- All actions logged to `sentry_audit.log` for compliance
- HIGH/CRITICAL actions require explicit human authorization — the system **never** executes destructive actions autonomously above MEDIUM severity

---

## 🙏 Built With

- [Elastic Cloud Serverless](https://elastic.co) — SIEM, detection rules, Agent Builder
- [Model Context Protocol](https://modelcontextprotocol.io) — AI tool integration
- [FastMCP](https://github.com/jlowin/fastmcp) — Python MCP server framework
- [Slack Block Kit](https://api.slack.com/block-kit) — Interactive approval UI
- [ngrok](https://ngrok.com) — Local tunnel for development

---

<div align="center">

Made with ❤️ for the Elastic Agent Builder Hackathon 2026

*"The best security response is the one that happens before the human notices."*

</div>