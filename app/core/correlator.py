"""
ChronosHunt Timeline Correlator & Dwell-Time Engine
Sorts multi-source forensic events, computes adversary dwell time,
identifies compromised hosts and accounts, and generates DFIR executive narratives.
"""

from typing import List, Dict, Any, Set
from datetime import datetime
from app.models.schemas import TimelineEvent, BreachCase


class TimelineCorrelator:
    @staticmethod
    def parse_time(ts_str: str) -> datetime:
        # Standardize ISO-8601 parsing
        clean_str = ts_str.replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(clean_str)
        except Exception:
            return datetime.utcnow()

    @classmethod
    def correlate(cls, case_id: str, case_name: str, threat_actor: str, target_org: str, incident_type: str, events: List[TimelineEvent]) -> BreachCase:
        if not events:
            now_iso = datetime.utcnow().isoformat()
            return BreachCase(
                id=case_id,
                case_name=case_name,
                threat_actor=threat_actor,
                target_organization=target_org,
                incident_type=incident_type,
                start_time=now_iso,
                end_time=now_iso,
                dwell_time_seconds=0,
                dwell_time_formatted="0 seconds",
                forensic_summary="No timeline events recorded.",
                timeline_events=[]
            )

        # Chronological sort
        sorted_events = sorted(events, key=lambda e: cls.parse_time(e.timestamp))

        start_dt = cls.parse_time(sorted_events[0].timestamp)
        end_dt = cls.parse_time(sorted_events[-1].timestamp)
        dwell_seconds = max(0, int((end_dt - start_dt).total_seconds()))

        # Format dwell time
        hours = dwell_seconds // 3600
        mins = (dwell_seconds % 3600) // 60
        secs = dwell_seconds % 60
        if hours > 0:
            dwell_fmt = f"{hours}h {mins}m {secs}s"
        elif mins > 0:
            dwell_fmt = f"{mins}m {secs}s"
        else:
            dwell_fmt = f"{secs}s"

        # Unique aggregations
        hosts: Set[str] = {e.host for e in sorted_events if e.host}
        users: Set[str] = {e.user for e in sorted_events if e.user and e.user != "SYSTEM"}
        mitre_ids: Set[str] = {f"[{e.mitre_id}] {e.mitre_name}" for e in sorted_events if e.mitre_id}
        
        # Extract adversary IPs
        ips: Set[str] = set()
        for e in sorted_events:
            if e.target_resource and any(c.isdigit() for c in e.target_resource) and "." in e.target_resource:
                ips.add(e.target_resource)
            if "C2" in (e.artifact_type or "") or "Logon" in (e.artifact_type or ""):
                if e.target_resource:
                    ips.add(e.target_resource)

        # Generate Forensic Executive Summary
        pivots = [e for e in sorted_events if e.is_adversary_pivot]
        summary = (
            f"Forensic investigation across {len(hosts)} endpoint(s) reveals a targeted {incident_type} intrusion "
            f"attributed to '{threat_actor}'. The intrusion spanned a total dwell time of {dwell_fmt}, beginning on "
            f"{sorted_events[0].timestamp} and culminating on {sorted_events[-1].timestamp}. "
            f"The attack chain exhibited {len(pivots)} major adversary pivot points and executed {len(mitre_ids)} distinct "
            f"MITRE ATT&CK techniques across {len(users)} compromised enterprise user accounts."
        )

        return BreachCase(
            id=case_id,
            case_name=case_name,
            threat_actor=threat_actor,
            target_organization=target_org,
            incident_type=incident_type,
            start_time=sorted_events[0].timestamp,
            end_time=sorted_events[-1].timestamp,
            dwell_time_seconds=dwell_seconds,
            dwell_time_formatted=dwell_fmt,
            affected_hosts=sorted(list(hosts)),
            compromised_accounts=sorted(list(users)),
            adversary_ips=sorted(list(ips)),
            mitre_techniques=sorted(list(mitre_ids)),
            forensic_summary=summary,
            timeline_events=sorted_events
        )
