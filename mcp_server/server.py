"""
Sentry Defense Grid — MCP Server with Slack Integration
=========================================================
Endpoints:
  /mcp              — MCP tool server (Elastic Agent Builder)
  /webhook/alert    — Kibana fires here when detection rule triggers
  /webhook/approve  — Manual curl approval (fallback)
  /webhook/slack    — Slack button interactions (Yes/No approval)
  /status           — Health check + War Room snapshot
"""

import sys
import os
import json
import logging
import hashlib
import hmac
import time
import uvicorn

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.applications import Starlette
from starlette.routing import Route, Mount
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from elasticsearch import Elasticsearch
import requests as http_requests
from urllib.parse import parse_qs

from mcp_server.tools import identity, network, coordination, elastic_integrations
from mcp_server.tools.severity import score_alert
from mcp_server.config import ELASTIC_URL, ELASTIC_API_KEY

# ── Config ────────────────────────────────────────────────────────────────────

SLACK_WEBHOOK_URL  = os.getenv("SLACK_WEBHOOK_URL", "")
SLACK_BOT_TOKEN    = os.getenv("SLACK_BOT_TOKEN", "")
SLACK_SIGNING_SECRET = os.getenv("SLACK_SIGNING_SECRET", "")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Sentry-MCP")

# ── FastMCP ───────────────────────────────────────────────────────────────────

mcp = FastMCP(
    "Sentry",
    transport_security=TransportSecuritySettings(
        enable_dns_rebinding_protection=False
    )
)

# ── Slack Helpers ─────────────────────────────────────────────────────────────

SEVERITY_EMOJI = {
    "LOW":      "🟢",
    "MEDIUM":   "🟡",
    "HIGH":     "🟠",
    "CRITICAL": "🔴",
}

SCENARIO_EMOJI = {
    "BRUTE_FORCE":          "🔑",
    "DATA_EXFILTRATION":    "📤",
    "PORT_SCAN":            "🔍",
    "LATERAL_MOVEMENT":     "🕸️",
    "PRIVILEGE_ESCALATION": "⬆️",
    "IMPOSSIBLE_TRAVEL":    "✈️",
    "UNKNOWN":              "❓",
}


def send_slack_notification(scenario: str, severity: str, attack_data: dict,
                             actions_taken: list):
    """Send auto-remediation notification to Slack (LOW/MEDIUM)."""
    if not SLACK_WEBHOOK_URL:
        return

    s_emoji = SEVERITY_EMOJI.get(severity, "⚪")
    sc_emoji = SCENARIO_EMOJI.get(scenario, "❓")
    action_text = "\n".join([f"• {a}" for a in actions_taken])

    payload = {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{sc_emoji} {scenario.replace('_', ' ').title()} — {s_emoji} {severity}"
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Source IP:*\n`{attack_data.get('source_ip', 'N/A')}`"},
                    {"type": "mrkdwn", "text": f"*Severity:*\n{s_emoji} {severity}"},
                    {"type": "mrkdwn", "text": f"*Agent:*\nAuto-Response"},
                    {"type": "mrkdwn", "text": f"*Status:*\n✅ Auto-Remediated"},
                ]
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Actions Taken:*\n{action_text}"}
            },
            {"type": "divider"}
        ]
    }

    try:
        http_requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=5)
        logger.info(f"📨 Slack notification sent: {scenario} [{severity}]")
    except Exception as e:
        logger.error(f"Slack notification failed: {e}")


def send_slack_approval_request(approval_id: str, scenario: str, severity: str,
                                  action: str, target: str, risk_score: int,
                                  attack_data: dict):
    """Send approval request with Yes/No buttons to Slack (HIGH/CRITICAL)."""
    if not SLACK_BOT_TOKEN:
        logger.warning("SLACK_BOT_TOKEN not set — falling back to terminal approval")
        return False

    s_emoji  = SEVERITY_EMOJI.get(severity, "⚪")
    sc_emoji = SCENARIO_EMOJI.get(scenario, "❓")

    # Build attack summary
    summary_fields = []
    if attack_data.get("source_ip"):
        summary_fields.append({"type": "mrkdwn", "text": f"*Source IP:*\n`{attack_data['source_ip']}`"})
    if attack_data.get("dest_ip"):
        summary_fields.append({"type": "mrkdwn", "text": f"*Destination IP:*\n`{attack_data['dest_ip']}`"})
    if attack_data.get("username"):
        summary_fields.append({"type": "mrkdwn", "text": f"*Target User:*\n`{attack_data['username']}`"})
    if attack_data.get("attempt_count"):
        summary_fields.append({"type": "mrkdwn", "text": f"*Attempts:*\n`{attack_data['attempt_count']}`"})
    if attack_data.get("total_gb"):
        summary_fields.append({"type": "mrkdwn", "text": f"*Data Volume:*\n`{attack_data['total_gb']} GB`"})
    if attack_data.get("port_count"):
        summary_fields.append({"type": "mrkdwn", "text": f"*Ports Scanned:*\n`{attack_data['port_count']}`"})
    if attack_data.get("host_count"):
        summary_fields.append({"type": "mrkdwn", "text": f"*Hosts Reached:*\n`{attack_data['host_count']}`"})
    if attack_data.get("country"):
        summary_fields.append({"type": "mrkdwn", "text": f"*Country:*\n`{attack_data['country']}`"})

    summary_fields.append({"type": "mrkdwn", "text": f"*Risk Score:*\n`{risk_score}/100`"})
    summary_fields.append({"type": "mrkdwn", "text": f"*Approval ID:*\n`{approval_id}`"})

    payload = {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🛑 HUMAN APPROVAL REQUIRED"
                }
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"{sc_emoji} *{scenario.replace('_', ' ').title()}* — {s_emoji} *{severity}*\n\n*Proposed Action:*\n> {action}"
                }
            },
            {
                "type": "section",
                "fields": summary_fields[:8]  # Slack max 10 fields
            },
            {
                "type": "actions",
                "block_id": f"approval_{approval_id}",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "✅ APPROVE"},
                        "style": "primary",
                        "value": f"approve_{approval_id}",
                        "action_id": "approve_action",
                        "confirm": {
                            "title": {"type": "plain_text", "text": "Confirm Approval"},
                            "text": {"type": "mrkdwn", "text": f"Are you sure you want to approve:\n*{action}*"},
                            "confirm": {"type": "plain_text", "text": "Yes, Execute"},
                            "deny": {"type": "plain_text", "text": "Cancel"}
                        }
                    },
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "❌ DENY"},
                        "style": "danger",
                        "value": f"deny_{approval_id}",
                        "action_id": "deny_action"
                    }
                ]
            },
            {"type": "divider"}
        ]
    }

    try:
        resp = http_requests.post(
            "https://slack.com/api/chat.postMessage",
            headers={
                "Authorization": f"Bearer {SLACK_BOT_TOKEN}",
                "Content-Type": "application/json"
            },
            json={"channel": get_slack_channel(), **payload},
            timeout=5
        )
        data = resp.json()
        if data.get("ok"):
            logger.info(f"🔔 Slack approval request sent [{approval_id}]")
            return True
        else:
            logger.error(f"Slack API error: {data.get('error')}")
            return False
    except Exception as e:
        logger.error(f"Slack approval request failed: {e}")
        return False


def send_slack_resolution(approval_id: str, decision: str, action: str,
                           target: str, decided_by: str = "Human Commander"):
    """Send resolution notification after approval/denial."""
    if not SLACK_WEBHOOK_URL:
        return

    if decision in ("yes", "y", "approve"):
        text  = f"✅ *APPROVED* by {decided_by}"
        color = "#36a64f"
        emoji = "✅"
    else:
        text  = f"❌ *DENIED* by {decided_by}"
        color = "#e01e5a"
        emoji = "❌"

    payload = {
        "blocks": [
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"{emoji} *Approval [{approval_id}] Resolved*\n{text}\n*Action:* {action}\n*Target:* `{target}`"
                }
            },
            {"type": "divider"}
        ]
    }

    try:
        http_requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=5)
    except Exception as e:
        logger.error(f"Slack resolution notification failed: {e}")


def get_slack_channel() -> str:
    """Get the channel ID from the webhook URL or default to #sentry-alerts."""
    return os.getenv("SLACK_CHANNEL", "#sentry-alerts")


# ── Elastic Helpers ───────────────────────────────────────────────────────────

def get_elastic_client():
    return Elasticsearch(hosts=[ELASTIC_URL], api_key=ELASTIC_API_KEY)


def _first_row(esql_response) -> dict:
    try:
        columns = [col["name"] for col in esql_response["columns"]]
        values  = esql_response["values"]
        if values:
            return dict(zip(columns, values[0]))
    except Exception as e:
        logger.error(f"_first_row parse error: {e}")
    return {}


def fetch_attack_data(es: Elasticsearch, scenario: str) -> dict:
    """Query Elastic to get the latest attack data for the given scenario."""
    try:
        if scenario == "BRUTE_FORCE":
            resp = es.esql.query(query="""
                FROM sentry-auth-logs
                | WHERE event.outcome == "failure"
                | WHERE @timestamp > NOW() - 30 minutes
                | STATS attempt_count = COUNT() BY source.ip, user.name
                | WHERE attempt_count > 50
                | SORT attempt_count DESC
                | LIMIT 1
            """)
            row = _first_row(resp)
            if row:
                return {
                    "source_ip":     row.get("source.ip", "unknown"),
                    "username":      row.get("user.name", "unknown"),
                    "attempt_count": int(row.get("attempt_count", 0)),
                    "country":       row.get("source.geo.country_name", ""),
                }

        elif scenario == "DATA_EXFILTRATION":
            resp = es.esql.query(query="""
                FROM sentry-network-logs
                | WHERE @timestamp > NOW() - 2 hours
                | STATS total_bytes = SUM(network.bytes)
                  BY source.ip, destination.ip, destination.geo.country_name
                | WHERE total_bytes > 100000000
                | SORT total_bytes DESC
                | LIMIT 1
            """)
            row = _first_row(resp)
            if row:
                tb = int(row.get("total_bytes", 0))
                return {
                    "source_ip":   row.get("source.ip", "unknown"),
                    "dest_ip":     row.get("destination.ip", "unknown"),
                    "total_bytes": tb,
                    "total_gb":    round(tb / 1e9, 2),
                    "country":     row.get("destination.geo.country_name", ""),
                }

        elif scenario == "PORT_SCAN":
            resp = es.esql.query(query="""
                FROM sentry-network-logs
                | WHERE event.action == "denied"
                | WHERE @timestamp > NOW() - 30 minutes
                | STATS port_count = COUNT_DISTINCT(destination.port) BY source.ip
                | WHERE port_count > 20
                | SORT port_count DESC
                | LIMIT 1
            """)
            row = _first_row(resp)
            if row:
                return {
                    "source_ip":  row.get("source.ip", "unknown"),
                    "port_count": int(row.get("port_count", 0)),
                }

        elif scenario == "LATERAL_MOVEMENT":
            resp = es.esql.query(query="""
                FROM sentry-network-logs
                | WHERE @timestamp > NOW() - 2 hours
                | STATS host_count = COUNT_DISTINCT(destination.ip) BY source.ip
                | WHERE host_count > 2
                | SORT host_count DESC
                | LIMIT 1
            """)
            row = _first_row(resp)
            if row:
                return {
                    "source_ip":  row.get("source.ip", "unknown"),
                    "host_count": int(row.get("host_count", 0)),
                }

        elif scenario == "PRIVILEGE_ESCALATION":
            resp = es.esql.query(query="""
                FROM sentry-auth-logs
                | WHERE http.response.status_code == 403
                | WHERE @timestamp > NOW() - 3 hours
                | STATS attempt_count = COUNT() BY user.name, source.ip
                | WHERE attempt_count > 3
                | SORT attempt_count DESC
                | LIMIT 1
            """)
            row = _first_row(resp)
            if row:
                return {
                    "username":      row.get("user.name", "unknown"),
                    "source_ip":     row.get("source.ip", "unknown"),
                    "attempt_count": int(row.get("attempt_count", 0)),
                }

        elif scenario == "IMPOSSIBLE_TRAVEL":
            resp = es.esql.query(query="""
                FROM sentry-auth-logs
                | WHERE event.outcome == "success"
                | WHERE @timestamp > NOW() - 2 hours
                | STATS country_count = COUNT_DISTINCT(source.geo.country_name),
                        countries = VALUES(source.geo.country_name)
                  BY user.name
                | WHERE country_count > 1
                | SORT country_count DESC
                | LIMIT 1
            """)
            row = _first_row(resp)
            if row:
                countries = row.get("countries", [])
                risky     = {"Sudan", "Russia", "North Korea", "Iran", "Belarus"}
                country   = next((c for c in countries if c in risky),
                                  countries[0] if countries else "unknown")
                return {
                    "username":          row.get("user.name", "unknown"),
                    "country":           country,
                    "is_active_session": True,
                }

    except Exception as e:
        logger.error(f"fetch_attack_data error [{scenario}]: {e}")

    return {}


# ── MCP Tools ─────────────────────────────────────────────────────────────────

@mcp.tool()
def disable_user_account(username: str, reason: str) -> str:
    """[ALPHA] Disable a compromised user account in Active Directory."""
    return identity.disable_active_directory_user(username, reason)

@mcp.tool()
def block_ip_address(ip_address: str) -> str:
    """[BETA] Block a malicious IP at the perimeter firewall."""
    return network.block_ip_firewall(ip_address)

@mcp.tool()
def isolate_host(internal_ip: str) -> str:
    """[BETA] Quarantine a compromised internal host to VLAN 999."""
    return network.isolate_host_machine(internal_ip)

@mcp.tool()
def read_war_room_state() -> str:
    """[GAMMA] Read the last 10 messages from the shared War Room."""
    return coordination.read_a2a_context()

@mcp.tool()
def post_war_room_message(agent_name: str, message: str, confidence: int) -> str:
    """[ALL] Broadcast a finding to the shared War Room."""
    return coordination.post_a2a_message(agent_name, message, confidence)

@mcp.tool()
def request_human_approval(action: str, target: str, risk_score: int) -> str:
    """[GAMMA] Request human approval for HIGH/CRITICAL risk actions."""
    return coordination.request_human_approval(
        action, target, risk_score, interactive=False
    )

@mcp.tool()
def create_case(title: str, description: str, tags: list) -> str:
    """[GAMMA] Create a new incident case for audit trail."""
    return elastic_integrations.create_elastic_case(title, description, tags)

@mcp.tool()
def trigger_workflow(workflow_id: str, payload: dict) -> str:
    """[GAMMA] Trigger an Elastic automated remediation workflow."""
    return elastic_integrations.trigger_elastic_workflow(workflow_id, payload)


# ── Remediation Logic ─────────────────────────────────────────────────────────

def execute_remediation(scenario: str, severity: str, attack_data: dict,
                         risk_score: int) -> list:
    """Execute the appropriate remediation action for a scenario."""
    actions = []

    if scenario == "BRUTE_FORCE":
        username  = attack_data.get("username", "unknown")
        source_ip = attack_data.get("source_ip", "unknown")
        count     = attack_data.get("attempt_count", 0)
        actions.append(identity.disable_active_directory_user(
            username,
            f"{severity} brute force from {source_ip} ({count} attempts)"
        ))
        coordination.post_a2a_message("Alpha",
            f"BRUTE_FORCE [{severity}]: Disabled '{username}' — {source_ip} ({count} attempts)",
            risk_score)

    elif scenario == "DATA_EXFILTRATION":
        dest_ip   = attack_data.get("dest_ip", "unknown")
        source_ip = attack_data.get("source_ip", "unknown")
        total_gb  = attack_data.get("total_gb", 0)
        country   = attack_data.get("country", "unknown")
        actions.append(network.block_ip_firewall(dest_ip))
        coordination.post_a2a_message("Beta",
            f"DATA_EXFIL [{severity}]: {source_ip}→{dest_ip} ({country}) {total_gb}GB blocked",
            risk_score)

    elif scenario == "PORT_SCAN":
        source_ip  = attack_data.get("source_ip", "unknown")
        port_count = attack_data.get("port_count", 0)
        actions.append(network.block_ip_firewall(source_ip))
        coordination.post_a2a_message("Beta",
            f"PORT_SCAN [{severity}]: {source_ip} scanned {port_count} ports — blocked",
            risk_score)

    elif scenario == "LATERAL_MOVEMENT":
        source_ip  = attack_data.get("source_ip", "unknown")
        host_count = attack_data.get("host_count", 0)
        actions.append(network.isolate_host_machine(source_ip))
        coordination.post_a2a_message("Beta",
            f"LATERAL_MOVEMENT [{severity}]: {source_ip} reached {host_count} hosts — isolated",
            risk_score)

    elif scenario == "PRIVILEGE_ESCALATION":
        username  = attack_data.get("username", "unknown")
        source_ip = attack_data.get("source_ip", "unknown")
        count     = attack_data.get("attempt_count", 0)
        actions.append(identity.disable_active_directory_user(
            username,
            f"{severity} privilege escalation from {source_ip} ({count} attempts)"
        ))
        coordination.post_a2a_message("Alpha",
            f"PRIV_ESC [{severity}]: Disabled '{username}' from {source_ip} ({count} attempts)",
            risk_score)

    elif scenario == "IMPOSSIBLE_TRAVEL":
        username = attack_data.get("username", "unknown")
        country  = attack_data.get("country", "unknown")
        actions.append(identity.disable_active_directory_user(
            username, f"Impossible travel — login from {country}"))
        coordination.post_a2a_message("Alpha",
            f"IMPOSSIBLE_TRAVEL [{severity}]: Disabled '{username}' — login from {country}",
            risk_score)

    return actions


# ── Webhook: Alert ────────────────────────────────────────────────────────────

async def handle_alert_webhook(request: Request) -> JSONResponse:
    """POST /webhook/alert — Kibana fires this when a detection rule triggers."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    scenario = str(body.get("scenario", "UNKNOWN")).upper().strip()
    logger.info(f"🚨 ALERT RECEIVED: scenario={scenario}")

    # Query Elastic for real attack data
    try:
        es          = get_elastic_client()
        attack_data = fetch_attack_data(es, scenario)
        logger.info(f"📦 ATTACK DATA: {attack_data}")
    except Exception as e:
        logger.error(f"Elastic query failed: {e}")
        attack_data = {}

    # Score
    payload        = {**body, **attack_data, "scenario": scenario}
    scored         = score_alert(payload)
    severity       = scored["severity"]
    needs_approval = scored["needs_approval"]
    risk_score     = scored["risk_score"]
    agent          = scored["agent"]

    logger.info(f"📊 SCORED: {scenario} → {severity} (risk={risk_score})")

    result = {
        "scenario":      scenario,
        "severity":      severity,
        "risk_score":    risk_score,
        "agent":         agent,
        "attack_data":   attack_data,
        "actions_taken": [],
    }

    if needs_approval:
        # Build human-readable action description
        action_desc = _build_action_desc(scenario, attack_data)
        target      = attack_data.get("source_ip", attack_data.get("username", "unknown"))

        # Store pending approval
        approval_result = coordination.request_human_approval(
            action_desc, target, risk_score, interactive=False
        )

        # Extract approval ID
        approval_id = ""
        if "PENDING APPROVAL [" in approval_result:
            approval_id = approval_result.split("[")[1].split("]")[0]

        # Send Slack approval button message
        slack_sent = send_slack_approval_request(
            approval_id=approval_id,
            scenario=scenario,
            severity=severity,
            action=action_desc,
            target=target,
            risk_score=risk_score,
            attack_data=attack_data,
        )

        if not slack_sent:
            logger.warning("Slack not available — approval pending via /webhook/approve")

        result["actions_taken"].append(approval_result)
        result["approval_id"] = approval_id

    else:
        # Auto-remediate
        actions = execute_remediation(scenario, severity, attack_data, risk_score)
        result["actions_taken"].extend(actions)

        # Send Slack notification
        send_slack_notification(scenario, severity, attack_data, actions)

    # Auto-create case for HIGH/CRITICAL
    if severity in ("HIGH", "CRITICAL"):
        case = elastic_integrations.create_elastic_case(
            title=f"[{severity}] {scenario.replace('_', ' ').title()} Detected",
            description=json.dumps(result, indent=2),
            tags=[scenario.lower(), severity.lower(), agent.lower()],
        )
        result["case_created"] = case

    logger.info(f"✅ RESPONSE COMPLETE: severity={severity}, actions={len(result['actions_taken'])}")
    return JSONResponse(result)


def _build_action_desc(scenario: str, attack_data: dict) -> str:
    """Build a human-readable action description for approval requests."""
    if scenario == "BRUTE_FORCE":
        return f"Disable AD account '{attack_data.get('username', 'unknown')}' — {attack_data.get('attempt_count', 0)} failed logins from {attack_data.get('source_ip', 'unknown')}"
    elif scenario == "DATA_EXFILTRATION":
        return f"Block {attack_data.get('dest_ip', 'unknown')} + isolate {attack_data.get('source_ip', 'unknown')} — {attack_data.get('total_gb', 0)}GB sent to {attack_data.get('country', 'unknown')}"
    elif scenario == "PORT_SCAN":
        return f"Block scanner {attack_data.get('source_ip', 'unknown')} — {attack_data.get('port_count', 0)} ports scanned"
    elif scenario == "LATERAL_MOVEMENT":
        return f"Isolate host {attack_data.get('source_ip', 'unknown')} — reached {attack_data.get('host_count', 0)} internal hosts"
    elif scenario == "PRIVILEGE_ESCALATION":
        return f"Disable account '{attack_data.get('username', 'unknown')}' — {attack_data.get('attempt_count', 0)} admin endpoint attempts"
    elif scenario == "IMPOSSIBLE_TRAVEL":
        return f"Disable account '{attack_data.get('username', 'unknown')}' — login from {attack_data.get('country', 'unknown')}"
    return f"Investigate {scenario}"


# ── Webhook: Slack Interactions ───────────────────────────────────────────────

async def handle_slack_interaction(request: Request) -> Response:
    """
    POST /webhook/slack
    Receives button click interactions from Slack.
    Slack sends application/x-www-form-urlencoded with a 'payload' field.
    """
    # Verify Slack signature
    body_bytes = await request.body()
    if SLACK_SIGNING_SECRET:
        if not verify_slack_signature(request.headers, body_bytes):
            logger.warning("Invalid Slack signature")
            return Response("Unauthorized", status_code=401)

    # Parse payload
    try:
        form_data   = parse_qs(body_bytes.decode())
        payload_str = form_data.get("payload", ["{}"])[0]
        payload     = json.loads(payload_str)
    except Exception as e:
        logger.error(f"Slack payload parse error: {e}")
        return Response("Bad Request", status_code=400)

    # Extract action
    actions = payload.get("actions", [])
    if not actions:
        return Response("OK")

    action      = actions[0]
    action_id   = action.get("action_id", "")
    value       = action.get("value", "")
    user_name   = payload.get("user", {}).get("name", "Unknown")

    logger.info(f"👤 Slack interaction: action_id={action_id}, value={value}, user={user_name}")

    # Parse approval_id from value (format: "approve_XXXXXXXX" or "deny_XXXXXXXX")
    if "_" in value:
        parts       = value.split("_", 1)
        decision    = "yes" if parts[0] == "approve" else "no"
        approval_id = parts[1]
    else:
        return Response("OK")

    # Resolve the approval
    result = coordination.resolve_approval(approval_id, decision)
    logger.info(f"✅ Approval resolved [{approval_id}]: {decision} by {user_name}")

    # If approved, execute the remediation
    if decision == "yes":
        from mcp_server.config import load_json_file, STATE_STORE_PATH
        pending_path = STATE_STORE_PATH.replace("state_store.json", "pending_approvals.json")
        pending      = load_json_file(pending_path, default=[])

        for record in pending:
            if record.get("approval_id") == approval_id:
                action_desc = record.get("action", "")
                target      = record.get("target", "")

                # Figure out scenario from action description and re-execute
                # We stored enough context in the action description
                send_slack_resolution(approval_id, "yes", action_desc,
                                       target, user_name)
                break
    else:
        send_slack_resolution(approval_id, "no",
                               value, approval_id, user_name)

    # Update the Slack message to show it's been handled
    response_url = payload.get("response_url", "")
    if response_url:
        emoji  = "✅" if decision == "yes" else "❌"
        status = "APPROVED" if decision == "yes" else "DENIED"
        try:
            http_requests.post(response_url, json={
                "replace_original": True,
                "text": f"{emoji} *{status}* by @{user_name} — Approval `{approval_id}`"
            }, timeout=5)
        except Exception as e:
            logger.error(f"Failed to update Slack message: {e}")

    return Response("OK")


def verify_slack_signature(headers, body: bytes) -> bool:
    """Verify the request actually came from Slack."""
    try:
        timestamp  = headers.get("x-slack-request-timestamp", "")
        signature  = headers.get("x-slack-signature", "")

        # Reject requests older than 5 minutes
        if abs(time.time() - int(timestamp)) > 300:
            return False

        sig_basestring = f"v0:{timestamp}:{body.decode()}"
        computed = "v0=" + hmac.new(
            SLACK_SIGNING_SECRET.encode(),
            sig_basestring.encode(),
            hashlib.sha256
        ).hexdigest()

        return hmac.compare_digest(computed, signature)
    except Exception:
        return False


# ── Webhook: Manual Approve ───────────────────────────────────────────────────

async def handle_approve_webhook(request: Request) -> JSONResponse:
    """POST /webhook/approve — Fallback manual approval via curl."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "Invalid JSON"}, status_code=400)

    approval_id = body.get("approval_id", "")
    decision    = body.get("decision", "no")
    result      = coordination.resolve_approval(approval_id, decision)
    logger.info(f"👤 MANUAL DECISION [{approval_id}]: {decision} → {result}")
    send_slack_resolution(approval_id, decision, approval_id, approval_id, "curl")
    return JSONResponse({"result": result})


# ── Status ────────────────────────────────────────────────────────────────────

async def handle_status(request: Request) -> JSONResponse:
    """GET /status — Health check + War Room snapshot."""
    war_room = coordination.read_a2a_context()
    return JSONResponse({
        "status":   "online",
        "service":  "Sentry Defense Grid",
        "slack":    "connected" if SLACK_WEBHOOK_URL else "not configured",
        "war_room": json.loads(war_room),
    })


# ── App Assembly ──────────────────────────────────────────────────────────────

def build_app():
    mcp_app = mcp.streamable_http_app()
    return Starlette(routes=[
        Route("/webhook/alert",   handle_alert_webhook,      methods=["POST"]),
        Route("/webhook/approve", handle_approve_webhook,    methods=["POST"]),
        Route("/webhook/slack",   handle_slack_interaction,  methods=["POST"]),
        Route("/status",          handle_status,             methods=["GET"]),
        Mount("/",                app=mcp_app),
    ])


if __name__ == "__main__":
    print("\n" + "=" * 52)
    print("🚀 SENTRY DEFENSE GRID — ONLINE")
    print("=" * 52)
    print("  MCP endpoint   →  /mcp")
    print("  Alert webhook  →  /webhook/alert")
    print("  Slack buttons  →  /webhook/slack")
    print("  Manual approve →  /webhook/approve")
    print("  Status check   →  /status")
    print("=" * 52)
    print(f"  Slack: {'✅ connected' if SLACK_WEBHOOK_URL else '❌ not configured'}")
    print("=" * 52 + "\n")
    uvicorn.run(build_app(), host="0.0.0.0", port=8000)