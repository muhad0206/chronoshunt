"""
ChronosHunt Data Models & Schemas
Structured schemas for digital forensics and incident response (DFIR),
multi-artifact timeline events, adversary pivots, and breach investigations.
"""

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from datetime import datetime, timezone


class TimelineEvent(BaseModel):
    id: str
    timestamp: str  # ISO-8601 UTC
    artifact_type: str  # SYSMON_PROC, PREFETCH, POWERSHELL_4104, SECURITY_4624, SECURITY_4672, MFT_FILE, NETWORK_C2, WEB_LOG
    kill_chain_phase: str  # INITIAL_ACCESS, EXECUTION, PERSISTENCE, PRIV_ESC, DEFENSE_EVASION, CRED_ACCESS, DISCOVERY, LATERAL_MOVEMENT, EXFILTRATION, IMPACT
    host: str
    user: str
    process_name: Optional[str] = None
    pid: Optional[int] = None
    parent_process: Optional[str] = None
    parent_pid: Optional[int] = None
    command_line: Optional[str] = None
    target_resource: Optional[str] = None  # file path, IP, or registry key
    mitre_id: Optional[str] = None
    mitre_name: Optional[str] = None
    severity: str = "MEDIUM"  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    is_adversary_pivot: bool = False
    pivot_description: Optional[str] = None
    raw_artifact: Dict[str, Any] = Field(default_factory=dict)


class BreachCase(BaseModel):
    id: str
    case_name: str
    threat_actor: str
    target_organization: str
    incident_type: str  # Ransomware, APT Espionage, Insider Threat, Web Compromise
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    start_time: str
    end_time: str
    dwell_time_seconds: int
    dwell_time_formatted: str
    affected_hosts: List[str] = Field(default_factory=list)
    compromised_accounts: List[str] = Field(default_factory=list)
    adversary_ips: List[str] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list)
    forensic_summary: str
    timeline_events: List[TimelineEvent] = Field(default_factory=list)


class CaseSubmission(BaseModel):
    case_name: str
    threat_actor: str = "Unknown Threat Actor"
    target_organization: str = "Enterprise Network"
    incident_type: str = "Suspicious Intrusion"
    raw_artifacts_json: str
