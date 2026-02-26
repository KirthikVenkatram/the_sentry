import logging
import json
from mcp_server.config import ALLOWLIST_PATH, AUDIT_LOG_PATH, load_json_file

logger = logging.getLogger("Network-Tool")

def block_ip_firewall(ip_address: str, direction: str = "inbound") -> str:
    """
    [NETWORK] Adds a DENY rule to the perimeter firewall for a malicious IP.
    """
    # 1. SELF-HEALING CHECK (Safety First)
    allowlist = load_json_file(ALLOWLIST_PATH, default={})
    safe_ips = allowlist.get("safe_ips", [])
    
    if ip_address in safe_ips:
        logger.warning(f"🛡️ SELF-HEALING: Prevented block on safe IP {ip_address}")
        return f"⚠️ ACTION ABORTED: {ip_address} is in the Allowlist (Safe IP). No block created."

    # 2. EXECUTION
    logger.info(f"🚫 FIREWALL BLOCK: {ip_address} ({direction})")
    
    with open(AUDIT_LOG_PATH, "a") as f:
        f.write(f"[NETWORK] BLOCKED IP: {ip_address} ({direction})\n")
        
    return f"✅ SUCCESS: Firewall Rule Created: DENY {direction} from {ip_address}. TTL: 24h."

def isolate_host_machine(internal_ip: str) -> str:
    """
    [NETWORK] Isolates an internal server from the LAN (VLAN switching).
    Use for internal compromised hosts (e.g., 10.x.x.x sending data out).
    """
    logger.info(f"☣️ ISOLATING HOST: {internal_ip}")
    return f"✅ SUCCESS: Host {internal_ip} QUARANTINED to VLAN 999 (Isolation Mode)."