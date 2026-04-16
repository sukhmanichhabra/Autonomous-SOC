"""
Log Analyzer Tools
==================
Provides log parsing and analysis capabilities.
Used by the Threat Analysis Agent to detect anomalies and
suspicious patterns in system/network logs.
"""

import re
from datetime import datetime
from typing import Optional
from collections import Counter


def analyze_logs(log_data: str) -> dict:
    """
    Analyze raw log data for security-relevant events.

    Args:
        log_data: Raw log text (syslog, auth.log, or similar format).

    Returns:
        Dictionary with analysis results including anomalies and statistics.
    """
    lines = log_data.strip().split("\n")
    analysis = {
        "total_lines": len(lines),
        "failed_logins": [],
        "suspicious_ips": [],
        "port_scans_detected": [],
        "privilege_escalations": [],
        "error_events": [],
        "summary": {},
    }

    failed_login_pattern = re.compile(
        r"(Failed password|authentication failure|invalid user)", re.IGNORECASE
    )
    port_scan_pattern = re.compile(
        r"(port scan|SYN flood|connection refused.*rapid)", re.IGNORECASE
    )
    priv_esc_pattern = re.compile(
        r"(sudo|su\s|privilege|escalat|root access)", re.IGNORECASE
    )
    ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    error_pattern = re.compile(r"(error|critical|alert|emergency)", re.IGNORECASE)

    ip_counter = Counter()

    for line in lines:
        # Detect failed logins
        if failed_login_pattern.search(line):
            analysis["failed_logins"].append(line.strip())
            ips = ip_pattern.findall(line)
            for ip in ips:
                ip_counter[ip] += 1

        # Detect port scan indicators
        if port_scan_pattern.search(line):
            analysis["port_scans_detected"].append(line.strip())

        # Detect privilege escalation attempts
        if priv_esc_pattern.search(line):
            analysis["privilege_escalations"].append(line.strip())

        # Detect error-level events
        if error_pattern.search(line):
            analysis["error_events"].append(line.strip())

    # Flag IPs with more than 5 failed attempts as suspicious
    analysis["suspicious_ips"] = [
        {"ip": ip, "failed_attempts": count}
        for ip, count in ip_counter.items()
        if count >= 3
    ]

    analysis["summary"] = {
        "total_failed_logins": len(analysis["failed_logins"]),
        "total_port_scans": len(analysis["port_scans_detected"]),
        "total_priv_escalations": len(analysis["privilege_escalations"]),
        "total_errors": len(analysis["error_events"]),
        "suspicious_ip_count": len(analysis["suspicious_ips"]),
        "risk_level": _calculate_risk_level(analysis),
    }

    return analysis


def parse_syslog(filepath: str) -> str:
    """
    Read and return contents of a syslog file.

    Args:
        filepath: Path to the syslog/log file.

    Returns:
        Raw log contents as a string.
    """
    try:
        with open(filepath, "r") as f:
            return f.read()
    except FileNotFoundError:
        return f"Error: Log file not found at {filepath}"
    except PermissionError:
        return f"Error: Permission denied reading {filepath}"


def _calculate_risk_level(analysis: dict) -> str:
    """Determine overall risk level based on analysis findings."""
    score = 0
    score += len(analysis["failed_logins"]) * 1
    score += len(analysis["port_scans_detected"]) * 3
    score += len(analysis["privilege_escalations"]) * 2
    score += len(analysis["suspicious_ips"]) * 5

    if score >= 20:
        return "CRITICAL"
    elif score >= 10:
        return "HIGH"
    elif score >= 5:
        return "MEDIUM"
    elif score >= 1:
        return "LOW"
    return "NONE"
