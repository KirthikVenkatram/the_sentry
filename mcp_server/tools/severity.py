"""
Sentry Severity Engine
======================
Scores incoming webhook alerts and decides:
  LOW / MEDIUM  → Agent acts autonomously
  HIGH          → Gamma requests human approval
  CRITICAL      → Gamma requests human approval + Slack page
"""

# ── Thresholds ────────────────────────────────────────────────────────────────

BRUTE_FORCE_THRESHOLDS = {
    "LOW":      (50,  100),
    "MEDIUM":   (100, 200),
    "HIGH":     (200, 500),
    "CRITICAL": (500, float("inf")),
}

EXFILTRATION_THRESHOLDS = {          # bytes
    "LOW":      (100_000_000,   500_000_000),   # 100 MB – 500 MB
    "MEDIUM":   (500_000_000, 1_000_000_000),   # 500 MB – 1 GB
    "HIGH":     (1_000_000_000, 5_000_000_000), # 1 GB – 5 GB
    "CRITICAL": (5_000_000_000, float("inf")),  # 5 GB+
}

PORT_SCAN_THRESHOLDS = {
    "LOW":      (20,  50),
    "MEDIUM":   (50, 100),
    "HIGH":     (100, 200),
    "CRITICAL": (200, float("inf")),
}

LATERAL_MOVEMENT_THRESHOLDS = {
    "LOW":      (2,  5),
    "MEDIUM":   (5, 10),
    "HIGH":     (10, 20),
    "CRITICAL": (20, float("inf")),
}

PRIVILEGE_ESCALATION_THRESHOLDS = {
    "LOW":      (1, 3),
    "MEDIUM":   (3, 5),
    "HIGH":     (5, float("inf")),
    "CRITICAL": (float("inf"), float("inf")),  # gaining admin = always HIGH
}

# High-risk countries bump severity by one level
HIGH_RISK_COUNTRIES = {
    "Sudan", "Russia", "North Korea", "Iran",
    "Ukraine", "Belarus", "Syria", "Venezuela"
}

SEVERITY_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

# ── Helpers ───────────────────────────────────────────────────────────────────

def _score(value: float, thresholds: dict) -> str:
    for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        lo, hi = thresholds[level]
        if lo <= value < hi:
            return level
    return "LOW"

def _bump(severity: str) -> str:
    idx = SEVERITY_ORDER.index(severity)
    return SEVERITY_ORDER[min(idx + 1, len(SEVERITY_ORDER) - 1)]

def needs_human_approval(severity: str) -> bool:
    return severity in ("HIGH", "CRITICAL")

# ── Public API ────────────────────────────────────────────────────────────────

def score_brute_force(attempt_count: int, country: str = "") -> dict:
    severity = _score(attempt_count, BRUTE_FORCE_THRESHOLDS)
    if country in HIGH_RISK_COUNTRIES:
        severity = _bump(severity)
    return {
        "scenario":        "BRUTE_FORCE",
        "severity":        severity,
        "needs_approval":  needs_human_approval(severity),
        "attempt_count":   attempt_count,
        "country":         country,
        "risk_score":      SEVERITY_ORDER.index(severity) * 25 + 10,
        "agent":           "Alpha",
        "action":          "disable_user_account",
    }

def score_exfiltration(total_bytes: int, country: str = "") -> dict:
    severity = _score(total_bytes, EXFILTRATION_THRESHOLDS)
    if country in HIGH_RISK_COUNTRIES:
        severity = _bump(severity)
    return {
        "scenario":        "DATA_EXFILTRATION",
        "severity":        severity,
        "needs_approval":  needs_human_approval(severity),
        "total_bytes":     total_bytes,
        "total_gb":        round(total_bytes / 1e9, 2),
        "country":         country,
        "risk_score":      SEVERITY_ORDER.index(severity) * 25 + 10,
        "agent":           "Beta",
        "action":          "block_ip_address + isolate_host",
    }

def score_port_scan(port_count: int, source_ip: str = "") -> dict:
    severity = _score(port_count, PORT_SCAN_THRESHOLDS)
    return {
        "scenario":       "PORT_SCAN",
        "severity":       severity,
        "needs_approval": needs_human_approval(severity),
        "port_count":     port_count,
        "source_ip":      source_ip,
        "risk_score":     SEVERITY_ORDER.index(severity) * 25 + 10,
        "agent":          "Beta",
        "action":         "block_ip_address",
    }

def score_lateral_movement(host_count: int, source_ip: str = "") -> dict:
    severity = _score(host_count, LATERAL_MOVEMENT_THRESHOLDS)
    return {
        "scenario":       "LATERAL_MOVEMENT",
        "severity":       severity,
        "needs_approval": needs_human_approval(severity),
        "host_count":     host_count,
        "source_ip":      source_ip,
        "risk_score":     SEVERITY_ORDER.index(severity) * 25 + 10,
        "agent":          "Beta",
        "action":         "isolate_host",
    }

def score_privilege_escalation(attempt_count: int, gained_admin: bool = False) -> dict:
    severity = _score(attempt_count, PRIVILEGE_ESCALATION_THRESHOLDS)
    if gained_admin:
        severity = "HIGH"
    return {
        "scenario":       "PRIVILEGE_ESCALATION",
        "severity":       severity,
        "needs_approval": needs_human_approval(severity),
        "attempt_count":  attempt_count,
        "gained_admin":   gained_admin,
        "risk_score":     SEVERITY_ORDER.index(severity) * 25 + 10,
        "agent":          "Alpha",
        "action":         "disable_user_account",
    }

def score_impossible_travel(country: str, is_active_session: bool = False) -> dict:
    severity = "MEDIUM" if country in HIGH_RISK_COUNTRIES else "LOW"
    if is_active_session:
        severity = _bump(severity)
    return {
        "scenario":        "IMPOSSIBLE_TRAVEL",
        "severity":        severity,
        "needs_approval":  needs_human_approval(severity),
        "country":         country,
        "is_active":       is_active_session,
        "risk_score":      SEVERITY_ORDER.index(severity) * 25 + 10,
        "agent":           "Alpha",
        "action":          "disable_user_account",
    }

def score_alert(payload: dict) -> dict:
    """
    Main entry point. Routes incoming webhook payload to the right scorer.
    Payload must contain 'scenario' key.
    """
    scenario = payload.get("scenario", "").upper()

    if scenario == "BRUTE_FORCE":
        return score_brute_force(
            attempt_count=int(payload.get("attempt_count", 0)),
            country=payload.get("country", ""),
        )
    elif scenario == "DATA_EXFILTRATION":
        return score_exfiltration(
            total_bytes=int(payload.get("total_bytes", 0)),
            country=payload.get("country", ""),
        )
    elif scenario == "PORT_SCAN":
        return score_port_scan(
            port_count=int(payload.get("port_count", 0)),
            source_ip=payload.get("source_ip", ""),
        )
    elif scenario == "LATERAL_MOVEMENT":
        return score_lateral_movement(
            host_count=int(payload.get("host_count", 0)),
            source_ip=payload.get("source_ip", ""),
        )
    elif scenario == "PRIVILEGE_ESCALATION":
        return score_privilege_escalation(
            attempt_count=int(payload.get("attempt_count", 0)),
            gained_admin=payload.get("gained_admin", False),
        )
    elif scenario == "IMPOSSIBLE_TRAVEL":
        return score_impossible_travel(
            country=payload.get("country", ""),
            is_active_session=payload.get("is_active_session", False),
        )
    else:
        return {
            "scenario":       "UNKNOWN",
            "severity":       "MEDIUM",
            "needs_approval": False,
            "risk_score":     50,
            "agent":          "Gamma",
            "action":         "investigate",
        }