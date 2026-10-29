"""
ChronosHunt Application Server
FastAPI backend providing REST APIs for forensic case management,
timeline reconstruction, dwell-time analytics, and serving the DFIR console.
"""

import json
from pathlib import Path
from typing import List, Dict, Optional
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware

from app.models.schemas import BreachCase, CaseSubmission, TimelineEvent
from app.core.normalizer import ArtifactNormalizer
from app.core.correlator import TimelineCorrelator

app = FastAPI(
    title="ChronosHunt - DFIR Forensic Timeline & Threat Hunting Engine",
    description="Multi-artifact event correlator and dwell-time analyzer for digital forensics and incident response.",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

CASES_STORE: Dict[str, BreachCase] = {}

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
SAMPLES_PATH = BASE_DIR / "data" / "sample_cases.json"


def seed_sample_cases():
    if not SAMPLES_PATH.exists():
        return
    try:
        with open(SAMPLES_PATH, "r") as f:
            raw_cases = json.load(f)
        for rc in raw_cases:
            events = [
                ArtifactNormalizer.normalize(a, default_host=rc.get("target_organization", "CORP"))
                for a in rc.get("artifacts", [])
            ]
            case = TimelineCorrelator.correlate(
                case_id=rc["id"],
                case_name=rc["case_name"],
                threat_actor=rc.get("threat_actor", "Unknown"),
                target_org=rc.get("target_organization", "Enterprise"),
                incident_type=rc.get("incident_type", "Intrusion"),
                events=events
            )
            CASES_STORE[case.id] = case
    except Exception as e:
        print(f"Error seeding sample cases: {e}")


@app.on_event("startup")
async def startup_event():
    seed_sample_cases()


# --- REST API Endpoints ---

@app.get("/api/cases", response_model=List[BreachCase])
async def get_all_cases():
    return list(CASES_STORE.values())


@app.get("/api/cases/{case_id}", response_model=BreachCase)
async def get_case(case_id: str):
    if case_id not in CASES_STORE:
        raise HTTPException(status_code=404, detail="Case not found")
    return CASES_STORE[case_id]


@app.post("/api/cases", response_model=BreachCase)
async def create_case(submission: CaseSubmission):
    try:
        raw_artifacts = json.loads(submission.raw_artifacts_json)
        if not isinstance(raw_artifacts, list):
            raise ValueError("Payload must be a JSON array of artifacts")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON artifacts: {e}")

    events = [
        ArtifactNormalizer.normalize(a, default_host=submission.target_organization)
        for a in raw_artifacts
    ]

    import uuid
    case_id = f"CASE-{uuid.uuid4().hex[:6].upper()}"

    case = TimelineCorrelator.correlate(
        case_id=case_id,
        case_name=submission.case_name,
        threat_actor=submission.threat_actor,
        target_org=submission.target_organization,
        incident_type=submission.incident_type,
        events=events
    )

    CASES_STORE[case.id] = case
    return case


@app.post("/api/cases/load-samples")
async def reload_samples():
    CASES_STORE.clear()
    seed_sample_cases()
    return {"message": "Forensic breach cases reloaded successfully", "count": len(CASES_STORE)}


@app.get("/api/metrics")
async def get_dfir_metrics():
    total_cases = len(CASES_STORE)
    total_events = sum(len(c.timeline_events) for c in CASES_STORE.values())
    total_pivots = sum(sum(1 for e in c.timeline_events if e.is_adversary_pivot) for c in CASES_STORE.values())
    avg_dwell = sum(c.dwell_time_seconds for c in CASES_STORE.values()) // max(1, total_cases)

    dwell_str = f"{avg_dwell // 60}m {avg_dwell % 60}s"

    return {
        "active_cases": total_cases,
        "correlated_artifacts": total_events,
        "identified_adversary_pivots": total_pivots,
        "average_adversary_dwell_time": dwell_str,
        "supported_forensic_parsers": ["Sysmon EVTX", "Prefetch (.pf)", "PowerShell 4104", "Security 4624/4672", "IIS Web Logs", "MFT Files"]
    }


@app.get("/api/cases/{case_id}/export", response_class=PlainTextResponse)
async def export_dfir_brief(case_id: str):
    if case_id not in CASES_STORE:
        raise HTTPException(status_code=404, detail="Case not found")
    case = CASES_STORE[case_id]

    report = f"""# [CHRONOSHUNT] DIGITAL FORENSICS & INCIDENT RESPONSE (DFIR) BRIEF
**Investigation**: {case.case_name} (ID: {case.id})
**Threat Actor**: {case.threat_actor}
**Incident Type**: {case.incident_type}
**Target Organization**: {case.target_organization}
**Adversary Dwell Time**: {case.dwell_time_formatted} ({case.dwell_time_seconds} seconds)
**Intrusion Window**: {case.start_time} to {case.end_time}

---

## 1. Executive Incident Summary
{case.forensic_summary}

## 2. Key Scoping Indicators
- **Compromised Hosts**: {', '.join(case.affected_hosts) if case.affected_hosts else 'None'}
- **Compromised Accounts**: {', '.join(case.compromised_accounts) if case.compromised_accounts else 'None'}
- **Adversary Infrastructure (C2 / Pivot IPs)**: {', '.join(case.adversary_ips) if case.adversary_ips else 'Internal Only'}

## 3. Mapped MITRE ATT&CK Matrix
"""
    for m in case.mitre_techniques:
        report += f"- {m}\n"

    report += f"""
## 4. Reconstructed Chronological Attack Timeline
| Timestamp (UTC) | Phase | Host | Artifact | Process / Command | Pivot Event |
| :--- | :--- | :--- | :--- | :--- | :--- |
"""
    for e in case.timeline_events:
        pivot_tag = f"**PIVOT**: {e.pivot_description}" if e.is_adversary_pivot else "-"
        cmd_safe = (e.command_line or "").replace("|", "\\|").replace("\n", " ")[:60]
        report += f"| `{e.timestamp}` | {e.kill_chain_phase} | {e.host} | {e.artifact_type} | `{cmd_safe}` | {pivot_tag} |\n"

    report += f"""
---
*Generated by ChronosHunt SOC Threat Hunting & Timeline Reconstructor*
"""
    return report


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/")
async def root():
    return FileResponse(STATIC_DIR / "index.html")
