"""
coordination.py — Agent-to-Agent communication + Human-in-the-Loop approval

KEY CHANGE: request_human_approval now works in TWO modes:
  - WEBHOOK mode (default): stores pending approval in state file,
    returns immediately so the server doesn't hang.
  - INTERACTIVE mode: original terminal input() for manual chat demos.
"""

import logging
import datetime
import json
import uuid
from mcp_server.config import STATE_STORE_PATH, load_json_file, save_json_file

logger = logging.getLogger("Coordination-Tool")

PENDING_APPROVALS_PATH = STATE_STORE_PATH.replace(
    "state_store.json", "pending_approvals.json"
)

# ── A2A War Room ──────────────────────────────────────────────────────────────

def post_a2a_message(agent_name: str, message: str, confidence: int) -> str:
    """
    [A2A PROTOCOL] Broadcasts a finding to the shared War Room context.
    All agents can read this to correlate threats.
    """
    entry = {
        "timestamp":  datetime.datetime.now().isoformat(),
        "sender":     agent_name,
        "confidence": confidence,
        "message":    message,
    }
    context = load_json_file(STATE_STORE_PATH, default=[])
    context.append(entry)
    save_json_file(STATE_STORE_PATH, context)

    logger.info(f"📡 [WAR ROOM] {agent_name} ({confidence}%): {message}")
    return "✅ Message broadcasted to War Room."


def read_a2a_context() -> str:
    """[A2A PROTOCOL] Returns the last 10 War Room messages."""
    context = load_json_file(STATE_STORE_PATH)
    if not context:
        return "[]"
    return json.dumps(context[-10:], indent=2)


# ── Human-in-the-Loop ────────────────────────────────────────────────────────

def request_human_approval(
    action: str,
    target: str,
    risk_score: int,
    interactive: bool = False,
) -> str:
    """
    [SAFETY] Requests human approval before a HIGH/CRITICAL action executes.

    WEBHOOK mode (interactive=False — default):
      Stores a pending approval record and returns immediately.
      The human approves via:  POST /webhook/approve  {"approval_id": "...", "decision": "yes"}

    INTERACTIVE mode (interactive=True):
      Blocks the terminal and waits for keyboard input.
      Use this when demoing via Agent Builder chat UI.
    """

    if interactive:
        # ── Terminal demo mode ────────────────────────────────────────────────
        print(f"\n{'='*52}")
        print(f"🛑  HIGH RISK ACTION — HUMAN APPROVAL REQUIRED")
        print(f"{'='*52}")
        print(f"  Action     : {action}")
        print(f"  Target     : {target}")
        print(f"  Risk Score : {risk_score}/100")
        print(f"{'='*52}")
        answer = input("⚠️  COMMANDER — Approve? (yes / no): ").strip().lower()

        if answer in ("yes", "y", "approve"):
            logger.info(f"✅ APPROVED: {action} on {target}")
            return f"✅ APPROVED: Human authorised '{action}' on '{target}'."
        else:
            logger.warning(f"❌ DENIED: {action} on {target}")
            return f"❌ DENIED: Human blocked '{action}' on '{target}'."

    else:
        # ── Webhook / async mode ──────────────────────────────────────────────
        approval_id = str(uuid.uuid4())[:8].upper()

        pending = load_json_file(PENDING_APPROVALS_PATH, default=[])
        pending.append({
            "approval_id": approval_id,
            "timestamp":   datetime.datetime.now().isoformat(),
            "action":      action,
            "target":      target,
            "risk_score":  risk_score,
            "status":      "PENDING",
        })
        save_json_file(PENDING_APPROVALS_PATH, pending)

        logger.warning(
            f"🛑 APPROVAL REQUIRED [{approval_id}]: {action} on {target} "
            f"(risk={risk_score})"
        )

        # Print visibly in server terminal so the demo presenter can see it
        print(f"\n{'='*52}")
        print(f"🛑  APPROVAL REQUIRED  [{approval_id}]")
        print(f"  Action     : {action}")
        print(f"  Target     : {target}")
        print(f"  Risk Score : {risk_score}/100")
        print(f"  Approve →  POST /webhook/approve")
        print(f"             {{\"approval_id\": \"{approval_id}\", \"decision\": \"yes\"}}")
        print(f"{'='*52}\n")

        return (
            f"⏳ PENDING APPROVAL [{approval_id}]: '{action}' on '{target}' "
            f"(risk={risk_score}/100). "
            f"Awaiting human decision at POST /webhook/approve"
        )


def resolve_approval(approval_id: str, decision: str) -> str:
    """Called by the /webhook/approve endpoint when the human responds."""
    pending = load_json_file(PENDING_APPROVALS_PATH, default=[])

    for record in pending:
        if record["approval_id"] == approval_id:
            record["status"]    = "APPROVED" if decision in ("yes", "y") else "DENIED"
            record["resolved"]  = datetime.datetime.now().isoformat()
            save_json_file(PENDING_APPROVALS_PATH, pending)

            if record["status"] == "APPROVED":
                logger.info(f"✅ APPROVED [{approval_id}]")
                return f"✅ APPROVED: '{record['action']}' on '{record['target']}' authorised."
            else:
                logger.warning(f"❌ DENIED [{approval_id}]")
                return f"❌ DENIED: '{record['action']}' on '{record['target']}' blocked."

    return f"⚠️ Approval ID '{approval_id}' not found."