"""
Sentry Defense Grid — MCP Server
==================================
Exposes tools to Elastic Agent Builder via streamable-http MCP transport.
Also hosts webhook endpoints so Kibana alert rules can trigger autonomous response.

Endpoints:
  /mcp              — MCP tool server (Elastic Agent Builder connects here)
  /webhook/alert    — Kibana fires here when a detection rule triggers
  /webhook/approve  — Human approves/denies a pending HIGH/CRITICAL action
  /status           — Health check + War Room snapshot
"""

import sys
import os
import json
import logging
import uvicorn

# Path fix — must be first
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.routing import Route, Mount
from starlette.requests import Request
from starlette.responses import JSONResponse

from mcp_server.tools import identity, network, coordination, elastic_integrations
from mcp_server.tools.severity import score_alert

# ── FastMCP Setup ─────────────────────────────────────────────────────────────

mcp = FastMCP(
    "Sentry",
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=False   # safe behind ngrok for dev
    )
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Sentry-MCP")

# ── MCP Tools — Identity (Agent Alpha) ───────────────────────────────────────

@mcp.tool()
def disable_user_account(username: str, reason: str) -> str:
    """
    [ALPHA] Disable a compromised user account in Active Directory.
    Use for: Brute Force, Impossible Travel, Privilege Escalation.
    """
    return identity.disable_active_directory_user(username, reason)

# ── MCP Tools — Network (Agent Beta) ─────────────────────────────────────────

@mcp.tool()
def block_ip_address(ip_address: str) -> str:
    """
    [BETA] Block a malicious IP at the perimeter firewall (inbound + outbound).
    Use for: Data Exfiltration, Port Scanning, Lateral Movement source IPs.
    """
    return network.block_ip_firewall(ip_address)

@mcp.tool()
def isolate_host(internal_ip: str) -> str:
    """
    [BETA] Quarantine a compromised internal host to VLAN 999 (no LAN access).
    Use for: Lateral Movement source hosts, confirmed exfiltration victims.
    """
    return network.isolate_host_machine(internal_ip)

# ── MCP Tools — Coordination (Agent Gamma) ────────────────────────────────────

@mcp.tool()
def read_war_room_state() -> str:
    """
    [GAMMA] Read the last 10 messages from the shared War Room.
    Use this to correlate findings from Alpha and Beta before escalating.
    """
    return coordination.read_a2a_context()

@mcp.tool()
def post_war_room_message(agent_name: str, message: str, confidence: int) -> str:
    """
    [ALL AGENTS] Broadcast a finding to the shared War Room.
    Always call this after taking any remediation action.
    Format: '[Scenario] detected from [IP/User]. Action: [what you did].'
    """
    return coordination.post_a2a_message(agent_name, message, confidence)

@mcp.tool()
def request_human_approval(action: str, target: str, risk_score: int) -> str:
    """
    [GAMMA] Request human commander approval for HIGH/CRITICAL risk actions.
    MANDATORY for risk_score >= 60. Do NOT skip this for high-risk actions.
    Returns a pending approval ID. Action executes only after human approves.
    """
    return coordination.request_human_approval(
        action, target, risk_score, interactive=False
    )

@mcp.tool()
def create_case(title: str, description: str, tags: list) -> str:
    """
    [GAMMA] Create a new incident case in Elastic Security for audit trail.
    Call this after all remediation actions are complete.
    """
    return elastic_integrations.create_elastic_case(title, description, tags)

@mcp.tool()
def trigger_workflow(workflow_id: str, payload: dict) -> str:
    """
    [GAMMA] Trigger an Elastic automated remediation workflow by ID.
    """
    return elastic_integrations.trigger_elastic_workflow(workflow_id, payload)

# ── Webhook Handlers ──────────────────────────────────────────────────────────

async def handle_alert_webhook(request: Request) -> JSONResponse:
    """
    POST /webhook/alert
    Kibana fires this when a detection rule triggers.
    Scores severity and routes to the right autonomous action.
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    logger.info(f"🚨 ALERT RECEIVED: {body}")

    # Score the alert
    scored = score_alert(body)
    severity      = scored["severity"]
    needs_approval = scored["needs_approval"]
    risk_score    = scored["risk_score"]
    scenario      = scored["scenario"]
    agent         = scored["agent"]

    logger.info(f"📊 SCORED: {scenario} → {severity} (risk={risk_score}, agent={agent})")

    result = {
        "scenario":    scenario,
        "severity":    severity,
        "risk_score":  risk_score,
        "agent":       agent,
        "actions_taken": [],
    }

    # ── Route by scenario + severity ─────────────────────────────────────────

    if scenario == "BRUTE_FORCE":
        username = body.get("username", "admin")
        source_ip = body.get("source_ip", "unknown")

        if needs_approval:
            approval = coordination.request_human_approval(
                action=f"Disable AD account for '{username}'",
                target=source_ip,
                risk_score=risk_score,
            )
            result["actions_taken"].append(approval)
        else:
            action = identity.disable_active_directory_user(
                username=username,
                reason=f"{severity} brute force from {source_ip} "
                       f"({body.get('attempt_count', '?')} attempts)"
            )
            coordination.post_a2a_message(
                "Alpha", f"BRUTE_FORCE [{severity}]: Disabled '{username}' "
                         f"— attacker {source_ip}", risk_score
            )
            result["actions_taken"].append(action)

    elif scenario == "DATA_EXFILTRATION":
        source_ip = body.get("source_ip", "unknown")
        dest_ip   = body.get("dest_ip", "unknown")

        if needs_approval:
            approval = coordination.request_human_approval(
                action=f"Block {dest_ip} + isolate {source_ip}",
                target=source_ip,
                risk_score=risk_score,
            )
            result["actions_taken"].append(approval)
        else:
            block  = network.block_ip_firewall(dest_ip)
            coordination.post_a2a_message(
                "Beta", f"EXFILTRATION [{severity}]: {source_ip} → {dest_ip} blocked",
                risk_score
            )
            result["actions_taken"].append(block)

    elif scenario == "PORT_SCAN":
        source_ip = body.get("source_ip", "unknown")
        block = network.block_ip_firewall(source_ip)
        coordination.post_a2a_message(
            "Beta", f"PORT_SCAN [{severity}]: {source_ip} blocked "
                    f"({body.get('port_count', '?')} ports scanned)", risk_score
        )
        result["actions_taken"].append(block)

    elif scenario == "LATERAL_MOVEMENT":
        source_ip = body.get("source_ip", "unknown")

        if needs_approval:
            approval = coordination.request_human_approval(
                action=f"Isolate host {source_ip}",
                target=source_ip,
                risk_score=risk_score,
            )
            result["actions_taken"].append(approval)
        else:
            isolate = network.isolate_host_machine(source_ip)
            coordination.post_a2a_message(
                "Beta", f"LATERAL_MOVEMENT [{severity}]: {source_ip} isolated "
                        f"({body.get('host_count', '?')} hosts reached)", risk_score
            )
            result["actions_taken"].append(isolate)

    elif scenario == "PRIVILEGE_ESCALATION":
        username  = body.get("username", "unknown")
        source_ip = body.get("source_ip", "unknown")

        if needs_approval:
            approval = coordination.request_human_approval(
                action=f"Disable account '{username}' (privilege escalation)",
                target=source_ip,
                risk_score=risk_score,
            )
            result["actions_taken"].append(approval)
        else:
            action = identity.disable_active_directory_user(
                username=username,
                reason=f"{severity} privilege escalation from {source_ip}"
            )
            coordination.post_a2a_message(
                "Alpha", f"PRIV_ESC [{severity}]: Disabled '{username}' "
                         f"from {source_ip}", risk_score
            )
            result["actions_taken"].append(action)

    elif scenario == "IMPOSSIBLE_TRAVEL":
        username = body.get("username", "unknown")
        country  = body.get("country", "unknown")
        action   = identity.disable_active_directory_user(
            username=username,
            reason=f"Impossible travel — login from {country}"
        )
        coordination.post_a2a_message(
            "Alpha", f"IMPOSSIBLE_TRAVEL [{severity}]: Disabled '{username}' "
                     f"(login from {country})", risk_score
        )
        result["actions_taken"].append(action)

    # Auto-create case for HIGH/CRITICAL
    if severity in ("HIGH", "CRITICAL"):
        case = elastic_integrations.create_elastic_case(
            title=f"[{severity}] {scenario.replace('_', ' ').title()} Detected",
            description=json.dumps(result, indent=2),
            tags=[scenario.lower(), severity.lower(), agent.lower()],
        )
        result["case_created"] = case

    logger.info(f"✅ RESPONSE COMPLETE: {result}")
    return JSONResponse(result)


async def handle_approve_webhook(request: Request) -> JSONResponse:
    """
    POST /webhook/approve
    Human sends approval/denial for a pending HIGH/CRITICAL action.
    Body: {"approval_id": "ABC12345", "decision": "yes"}
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    approval_id = body.get("approval_id", "")
    decision    = body.get("decision", "no")

    result = coordination.resolve_approval(approval_id, decision)
    logger.info(f"👤 HUMAN DECISION [{approval_id}]: {decision} → {result}")
    return JSONResponse({"result": result})


async def handle_status(request: Request) -> JSONResponse:
    """GET /status — Health check + War Room snapshot"""
    war_room = coordination.read_a2a_context()
    return JSONResponse({
        "status":   "online",
        "service":  "Sentry Defense Grid",
        "war_room": json.loads(war_room),
    })


# ── App Assembly ──────────────────────────────────────────────────────────────

def build_app():
    mcp_app = mcp.streamable_http_app()

    return Starlette(routes=[
        Route("/webhook/alert",   handle_alert_webhook,  methods=["POST"]),
        Route("/webhook/approve", handle_approve_webhook, methods=["POST"]),
        Route("/status",          handle_status,          methods=["GET"]),
        Mount("/",                app=mcp_app),
    ])


if __name__ == "__main__":
    print("\n" + "="*52)
    print("🚀 SENTRY DEFENSE GRID — ONLINE")
    print("="*52)
    print("  MCP endpoint  →  /mcp")
    print("  Alert webhook →  /webhook/alert")
    print("  Approve HiRisk → /webhook/approve")
    print("  Status check  →  /status")
    print("="*52)
    print("  Run ngrok:  ngrok http 8000")
    print("="*52 + "\n")

    uvicorn.run(build_app(), host="0.0.0.0", port=8000)