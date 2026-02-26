import logging
from mcp_server.config import AUDIT_LOG_PATH

logger = logging.getLogger("Identity-Tool")

def disable_active_directory_user(username: str, reason: str) -> str:
    """
    [IDENTITY] Disables a user account globally in Active Directory.
    Use this immediately when you detect a Brute Force attack (e.g., >50 failures).
    """
    logger.warning(f"🔒 LOCKING USER: {username} | Reason: {reason}")
    
    # In a real environment, this would call Microsoft Graph API / LDAP
    # For the demo, we log the enforcement action to the audit file.
    
    with open(AUDIT_LOG_PATH, "a") as f:
        f.write(f"[IDENTITY] DISABLED USER: {username} REASON: {reason}\n")
        
    return f"✅ SUCCESS: User '{username}' has been DISABLED. Active sessions terminated."