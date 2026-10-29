"""
ChronosHunt Multi-Artifact Forensic Normalizer
Ingests heterogeneous DFIR artifacts (Sysmon, Prefetch, PowerShell 4104,
Windows Security 4624/4672, MFT File records, and Web Server logs)
and normalizes them into chronologically aligned TimelineEvents.
"""

import uuid
from typing import Dict, Any, Optional
from datetime import datetime
from app.models.schemas import TimelineEvent


class ArtifactNormalizer:
    @staticmethod
    def normalize(raw: Dict[str, Any], default_host: str = "HOST-01", default_user: str = "SYSTEM") -> TimelineEvent:
        event_id_str = f"EVT-{uuid.uuid4().hex[:8].upper()}"
        timestamp = raw.get("timestamp") or raw.get("TimeCreated") or raw.get("@timestamp") or datetime.utcnow().isoformat()
        source = raw.get("source_type") or raw.get("artifact_type") or "UNKNOWN"

        host = raw.get("host") or raw.get("Computer") or default_host
        user = raw.get("user") or raw.get("User") or raw.get("AccountName") or default_user

        # 1. Sysmon Process Creation (Event ID 1)
        if source == "SYSMON_PROC" or raw.get("EventID") == 1:
            cmd = raw.get("CommandLine") or raw.get("command_line") or ""
            image = raw.get("Image") or raw.get("process_name") or "process.exe"
            proc_name = image.split("\\")[-1].split("/")[-1]
            parent_image = raw.get("ParentImage") or raw.get("parent_process")
            parent_name = parent_image.split("\\")[-1].split("/")[-1] if parent_image else None

            kill_chain = ArtifactNormalizer._infer_kill_chain(proc_name, cmd, parent_name)
            mitre_id, mitre_name = ArtifactNormalizer._infer_mitre(proc_name, cmd, parent_name)
            is_pivot, pivot_desc = ArtifactNormalizer._detect_pivot(proc_name, cmd, parent_name, kill_chain)

            return TimelineEvent(
                id=event_id_str,
                timestamp=timestamp,
                artifact_type="SYSMON_PROC",
                kill_chain_phase=kill_chain,
                host=host,
                user=user,
                process_name=proc_name,
                pid=raw.get("ProcessId"),
                parent_process=parent_name,
                parent_pid=raw.get("ParentProcessId"),
                command_line=cmd,
                target_resource=raw.get("CurrentDirectory"),
                mitre_id=mitre_id,
                mitre_name=mitre_name,
                severity=raw.get("severity", "HIGH" if is_pivot else "MEDIUM"),
                is_adversary_pivot=is_pivot,
                pivot_description=pivot_desc,
                raw_artifact=raw
            )

        # 2. Windows Prefetch (.pf) Execution Record
        elif source == "PREFETCH" or "prefetch" in source.lower():
            proc_name = raw.get("executable") or raw.get("process_name") or "APPLICATION.EXE"
            run_count = raw.get("run_count", 1)
            kill_chain = ArtifactNormalizer._infer_kill_chain(proc_name, "", None)
            mitre_id, mitre_name = ArtifactNormalizer._infer_mitre(proc_name, "", None)

            is_pivot = proc_name.lower() in ["procdump.exe", "mimikatz.exe", "vssadmin.exe", "psexec.exe", "certutil.exe"]
            pivot_desc = f"First-time Prefetch execution of adversary utility: {proc_name}" if is_pivot else None

            return TimelineEvent(
                id=event_id_str,
                timestamp=timestamp,
                artifact_type="PREFETCH",
                kill_chain_phase=kill_chain,
                host=host,
                user=user,
                process_name=proc_name,
                command_line=f"[Prefetch Execution Record] Run Count: {run_count} | Path: {raw.get('file_path', 'C:\\Windows\\Prefetch')}",
                target_resource=raw.get("file_path"),
                mitre_id=mitre_id,
                mitre_name=mitre_name,
                severity="HIGH" if is_pivot else "INFO",
                is_adversary_pivot=is_pivot,
                pivot_description=pivot_desc,
                raw_artifact=raw
            )

        # 3. PowerShell ScriptBlock (Event ID 4104)
        elif source == "POWERSHELL_4104" or raw.get("EventID") == 4104:
            script_content = raw.get("ScriptBlockText") or raw.get("payload") or ""
            is_pivot = any(k in script_content.lower() for k in ["downloadstring", "invoke-mimikatz", "bypass", "hidden", "frombase64string"])
            pivot_desc = "De-obfuscated PowerShell ScriptBlock executing in-memory memory payload" if is_pivot else None

            return TimelineEvent(
                id=event_id_str,
                timestamp=timestamp,
                artifact_type="POWERSHELL_4104",
                kill_chain_phase="EXECUTION",
                host=host,
                user=user,
                process_name="powershell.exe",
                command_line=script_content,
                mitre_id="T1059.001",
                mitre_name="PowerShell ScriptBlock Execution",
                severity="CRITICAL" if is_pivot else "MEDIUM",
                is_adversary_pivot=is_pivot,
                pivot_description=pivot_desc,
                raw_artifact=raw
            )

        # 4. Windows Security Logon (Event ID 4624) or Privilege Elevation (4672)
        elif source in ["SECURITY_4624", "SECURITY_4672"] or raw.get("EventID") in [4624, 4672]:
            event_id = raw.get("EventID", 4624)
            logon_type = raw.get("LogonType", 3)  # 3 = Network (SMB/Lateral), 10 = RemoteInteractive (RDP)
            src_ip = raw.get("IpAddress") or raw.get("source_ip") or "127.0.0.1"

            if event_id == 4672:
                is_pivot = True
                pivot_desc = f"Administrative Privilege Assignment (SeDebugPrivilege / SeTcbPrivilege) for user {user}"
                phase = "PRIV_ESC"
                mitre_id = "T1078.002"
                mitre_name = "Valid Accounts: Domain Accounts"
            else:
                is_pivot = logon_type in [3, 10] and src_ip not in ["127.0.0.1", "-", "::1"]
                pivot_desc = f"Lateral Network Logon (Type {logon_type}) from external/workstation IP: {src_ip}" if is_pivot else None
                phase = "LATERAL_MOVEMENT" if is_pivot else "INITIAL_ACCESS"
                mitre_id = "T1021.002" if logon_type == 3 else "T1021.001"
                mitre_name = "SMB/Windows Admin Shares" if logon_type == 3 else "Remote Desktop Protocol"

            return TimelineEvent(
                id=event_id_str,
                timestamp=timestamp,
                artifact_type="SECURITY_LOGON",
                kill_chain_phase=phase,
                host=host,
                user=user,
                process_name="lsass.exe",
                command_line=f"Security Event {event_id}: Logon Type {logon_type} from {src_ip}",
                target_resource=src_ip,
                mitre_id=mitre_id,
                mitre_name=mitre_name,
                severity="HIGH" if is_pivot else "LOW",
                is_adversary_pivot=is_pivot,
                pivot_description=pivot_desc,
                raw_artifact=raw
            )

        # 5. Fallback Generic Event
        proc = raw.get("process_name") or raw.get("executable") or "system.exe"
        cmd = raw.get("command_line") or raw.get("description") or ""
        phase = ArtifactNormalizer._infer_kill_chain(proc, cmd, None)
        mitre_id, mitre_name = ArtifactNormalizer._infer_mitre(proc, cmd, None)

        return TimelineEvent(
            id=event_id_str,
            timestamp=timestamp,
            artifact_type=source,
            kill_chain_phase=phase,
            host=host,
            user=user,
            process_name=proc,
            command_line=cmd,
            target_resource=raw.get("target"),
            mitre_id=mitre_id,
            mitre_name=mitre_name,
            severity=raw.get("severity", "MEDIUM"),
            is_adversary_pivot=raw.get("is_pivot", False),
            pivot_description=raw.get("pivot_description"),
            raw_artifact=raw
        )

    @staticmethod
    def _infer_kill_chain(proc_name: str, cmd: str, parent: Optional[str]) -> str:
        cmd_l = (cmd or "").lower()
        proc_l = (proc_name or "").lower()
        parent_l = (parent or "").lower()

        if any(w in cmd_l for w in ["w3wp.exe", "shell.aspx", "jsp", "php", "cve-"]):
            return "INITIAL_ACCESS"
        if any(w in cmd_l for w in ["vssadmin", "delete shadows", "inhibit", "encrypt", ".locked"]):
            return "IMPACT"
        if any(w in cmd_l for w in ["lsass", "procdump", "mimikatz", "sekurlsa", "sam"]):
            return "CRED_ACCESS"
        if any(w in cmd_l for w in ["psexec", "wmiexec", "smb", "winrm", "admin$", "c$"]):
            return "LATERAL_MOVEMENT"
        if any(w in cmd_l for w in ["whoami", "nltest", "net user", "net group", "bloodhound", "adfind"]):
            return "DISCOVERY"
        if any(w in cmd_l for w in ["schtasks /create", "reg add", "currentversion\\run", "startup"]):
            return "PERSISTENCE"
        if any(w in cmd_l for w in ["curl", "certutil -urlcache", "bitsadmin", "mega.nz", "rclone", "7z a", "rar a"]):
            return "EXFILTRATION"
        if parent_l in ["winword.exe", "excel.exe", "outlook.exe"] and proc_l in ["powershell.exe", "cmd.exe"]:
            return "INITIAL_ACCESS"

        return "EXECUTION"

    @staticmethod
    def _infer_mitre(proc_name: str, cmd: str, parent: Optional[str]) -> (str, str):
        combined = f"{proc_name} {cmd} {parent or ''}".lower()

        if "vssadmin" in combined and "delete shadows" in combined:
            return "T1490", "Inhibit System Recovery"
        if "procdump" in combined or "lsass" in combined:
            return "T1003.001", "OS Credential Dumping: LSASS Memory"
        if "powershell" in combined:
            return "T1059.001", "Command and Scripting Interpreter: PowerShell"
        if "certutil" in combined:
            return "T1105", "Ingress Tool Transfer"
        if "schtasks" in combined:
            return "T1053.005", "Scheduled Task/Job: Scheduled Task"
        if "psexec" in combined or "admin$" in combined:
            return "T1021.002", "SMB/Windows Admin Shares"
        if "whoami" in combined:
            return "T1033", "System Owner/User Discovery"
        if "bloodhound" in combined or "sharphound" in combined:
            return "T1087.002", "Account Discovery: Domain Account"
        if "7z" in combined or "rar" in combined:
            return "T1560.001", "Archive Collected Data: Archive via Utility"
        if "winword" in (parent or "").lower():
            return "T1204.002", "User Execution: Malicious File"

        return "T1059", "Command and Scripting Interpreter"

    @staticmethod
    def _detect_pivot(proc_name: str, cmd: str, parent: Optional[str], phase: str) -> (bool, Optional[str]):
        parent_l = (parent or "").lower()
        proc_l = (proc_name or "").lower()
        cmd_l = (cmd or "").lower()

        if parent_l in ["winword.exe", "excel.exe"] and proc_l in ["powershell.exe", "cmd.exe"]:
            return True, f"Initial Compromise Foothold: Office macro spawned '{proc_name}' shell"
        if "procdump" in cmd_l and "lsass" in cmd_l:
            return True, "Major Threat Escalation: LSASS process memory dump for credential extraction"
        if "vssadmin" in cmd_l and "delete shadows" in cmd_l:
            return True, "Ransomware Hallmark Pivot: Volume Shadow Copies purged to prevent disaster recovery"
        if "psexec" in cmd_l or "admin$" in cmd_l:
            return True, "Lateral Movement Pivot: Host-to-host execution across internal enterprise boundary"
        if any(tool in cmd_l for tool in ["bloodhound", "sharphound"]):
            return True, "Active Directory Reconnaissance Pivot: Mass domain privilege graph enumeration"

        return False, None
