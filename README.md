# SOC Honeypot Project Report

**Author:** Ofentse Phalane  
**Platform:** Microsoft Azure  
**Project:** Cloud-Based Honeypot for Threat Analysis & Incident Response

## 1. Objective

To deploy a vulnerable ("honeypot") Windows 10 virtual machine in Microsoft Azure, intentionally expose it to the internet, monitor attacks, perform forensic analysis, and demonstrate complete SOC incident response capabilities using Microsoft Sentinel and Log Analytics Workspace (LAW).

## 2. Setup & Deployment

### 2.1 Virtual Machine Creation

- Logged into Azure Portal.
- Created a Windows 10 VM under resource group `RG-SOC-LAB`.
- **VM Name:** CORP-NET-EAST-1
- **Size:** Standard_B1s
- Public IP enabled.
- Saved admin credentials for remote access.

<p align="center">
Virtual Machine: <br/>
 
<img src="https://imgur.com/u7kyiUn.png" alt="Virtual Machine"/>
    
<br />
</p>

### 2.2 Network Security Configuration

Accessed the VM's Network Security Group (NSG) and created an inbound rule allowing all traffic:

| Setting     | Value |
|------------|-------|
| Source     | Any   |
| Destination| Any   |
| Port       | Any   |
| Protocol   | Any   |
| Action     | Allow |

<p align="center">
Virtual Machine: <br/>
<img src="https://imgur.com/wSfTXkE.png" alt="Virtual Machine"/>
<br />
</p>

### 2.3 Firewall Disabled

- Logged into the VM via RDP.
- Executed `wf.msc` → Disabled firewall for all profiles.

<p align="center">
Virtual Machine: <br/>
<img src="https://imgur.com/1K5xnrQ.png" alt="Virtual Machine"/>
<br />
</p>

## 3. Attack Simulation & Evidence

### 3.1 Brute Force Attempt

- Multiple failed RDP logins performed using username `employee`.
- Event Viewer → Security Logs → Event ID `4625` (Failed Login).

<p align="center">
Virtual Machine: <br/>
<img src="https://imgur.com/fxA4djT.png" alt="Virtual Machine"/>
<br />
</p>

### 3.2 Log Forwarding Setup

- Created Log Analytics Workspace (LAW).
- Deployed Microsoft Sentinel and connected LAW.
- Configured Windows Security Events via AMA connector.

<p align="center">
Log Forwarding: <br/>
<img src="https://imgur.com/tcXNj8B.png" alt="Log Forwarding"/>
<br />
</p>

### 3.3 KQL Query Execution

Used the following query to analyze failed logins:

```kql
SecurityEvent
| where EventID == 4625
| project TimeGenerated, Account, IpAddress, Computer
```

<p align="center">
Log Forwarding: <br/>
<img src="https://imgur.com/S22MHHf.png" alt="Log Forwarding"/>
<br />
</p>

## 4. Log Enrichment & Geo-IP Mapping

### 4.1 Geo-IP Lookup

Imported geoip-summarized.csv as a Sentinel Watchlist.

Used ipv4_lookup() to enrich IP logs with country and city data:

```kql
let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent
    | where EventID == 4625
    | order by TimeGenerated desc
    | evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network);
WindowsEvents
```

<p align="center">
geoip_lookup: <br/>
<img src="https://imgur.com/POAObhd.png" alt="geoip_lookup"/>
<br />
</p>

### 4.2 Attack Map Creation

Built Attack Map in Sentinel Workbook using map.json.

Visualized attacker IPs geographically.

<p align="center">
attack_map: <br/>
<img src="https://imgur.com/nlgJjHM.png" alt="attack_map"/>
<br />
</p>

## 5. Incident Response Lifecycle

### Phase 1: Identification

#### Successful Unauthorized Logins (Event ID 4624)

This section documents all successful RDP logins into the honeypot VM.
Event ID 4624 (LogonType 10) indicates that an attacker successfully authenticated via Remote Desktop Protocol.

<p align="center">
 <br/>
<img src="https://imgur.com/gZ1EW4j.png" alt="attack_map"/>
<br />
</p>

#### Summary of Successful Login Attempts

This section provides a summary of all Event ID 4624 entries, filtered by LogonType 2, 3, and 10 (indicating interactive, network, and remote logons). These logs represent all successful authentications to the honeypot VM.

**KQL Query Used:**

```kql
SecurityEvent
| where EventID == 4624
| where LogonType in (2, 3, 10)
| project TimeGenerated, Account, LogonType, IpAddress, Computer
| sort by TimeGenerated desc
```

#### Observed Successful Logins

| Timestamp (UTC) | Account | Logon Type | Source IP | Target Host | Notes |
|----------------|---------|------------|-----------|-------------|-------|
| 2025-11-09 18:57:21 | Window Manager\DWM-1 | 2 | - | CORP-NET-EAST-1 | OS internal login |
| 2025-11-06 10:04:16 | CORP-NET-EAST-1\labuser | 3 | 165.16.188.135 | CORP-NET-EAST-1 | External login |
| 2025-11-06 10:02:37 | CORP-NET-EAST-1\labuser | 3 | 105.245.20.121 | CORP-NET-EAST-1 | External login |
| 2025-11-06 09:40:55 | NT AUTHORITY\ANONYMOUS LOGON | 3 | 35.195.43.11 | CORP-NET-EAST-1 | Likely automated probe |
| 2025-11-07 10:03:30 | NT AUTHORITY\ANONYMOUS LOGON | 3 | 102.213.28.196 | CORP-NET-EAST-1 | - |

### Phase 2: Containment

Containment actions were taken after identifying multiple successful logins from external, unauthorized IP addresses. The goal was to stop ongoing access, prevent further compromise, and preserve evidence for analysis.

#### Immediate Containment Actions Taken

##### 1. Identified Malicious IP Addresses

The following IPs successfully authenticated to the honeypot and were classified as malicious:

- 165.16.188.135
- 105.245.20.121
- 35.195.43.11
- 102.213.28.196

These addresses attempted repeated LogonType 3 (network) logins using the honeypot account.

##### 2. Blocked IP Addresses on Azure Network Security Group (NSG)

- Created inbound deny rules blocking the malicious IP ranges.
- Applied rules immediately on the VM's public-facing NSG.
- Confirmed that further login attempts stopped afterward.

##### 3. Disabled Remote Access to the VM

- Temporarily disabled RDP (TCP 3389) exposure to the internet.
- Restricted RDP access to internal-only or secure-admin IPs.
- Ensured no new external successful logins occurred.

##### 4. Locked the Compromised Account

- Disabled the "labuser" account used by attackers.
- Reset the password to a complex, non-guessable value.
- Removed unnecessary local accounts to reduce attack surface.

##### 5. Captured Evidence Before Making Changes

To preserve forensic integrity, the following evidence was collected:

- Full export of Azure Security Logs for Event ID 4624
- Screenshots of KQL queries showing successful logins
- VM-level Windows Security logs
- NSG flow logs showing inbound traffic
- Timestamped login sequences for timeline creation

No system files were altered before evidence collection.

#### Additional Containment Measures

##### Strengthened VM Access Controls

- Enforced Network-Level Authentication (NLA).
- Enabled account lockout policy to slow brute-force attacks.
- Disabled SMBv1 and unnecessary Windows services.

##### Implemented Alerting in Microsoft Sentinel

Created alerts for:

- Event ID 4624 from external IP addresses
- Event ID 4625 repeated failures
- Anonymous logins (NT AUTHORITY\ANONYMOUS LOGON)

Alerts now trigger email notifications.

<p align="center">
 <br/>
<img src="https://imgur.com/qUrylnx.png" alt="attack_map"/>
<br />
</p>

### Phase 3: Eradication

- Temporarily disconnected VM from the network.
- Removed attacker persistence by checking:
  - Scheduled Tasks
  - PowerShell history
  - Startup services
- Collected forensic artifacts (C:\Forensics\collection.zip):
  - Security.evtx
  - System.evtx
  - PowerShell_history.txt
  - Suspicious binaries

### Phase 4: Recovery

#### Restore from Clean Snapshot

The VM's OS disk was restored from a previously taken clean snapshot.
This ensures the VM is free from malware, unauthorized tasks, and attacker persistence.
Verified that system logs and accounts are back to baseline.

<p align="center">
<br/>
<img src="https://imgur.com/BkCgudi.png" alt="attack_map"/>
<br />
</p>

#### Remove "Allow Any" NSG Rule

Deleted the overly permissive Allow All inbound rule in the NSG.
Verified that only approved access is allowed via NSG rules.

<p align="center">
 <br/>
<img src="https://imgur.com/l6xOmtd.png" alt="attack_map"/>
<br />
</p>

#### Sentinel Alert Rule

Create a new Scheduled query rule
Query for EventID 4625 (failed logins)
Action: Send email/Teams alert

<p align="center">
 <br/>
<img src="https://imgur.com/wfnU2By.png" alt="attack_map"/>
<br />
</p>

### Phase 5: Lessons Learned

| Lesson | Description |
|--------|-------------|
| Exposed RDP ports are high-risk | Restrict using JIT and NSG. |
| Sentinel alerts effective | Automated detection of brute-force attempts. |
| Cloud Shell useful | Simplifies containment via CLI commands. |
| Snapshots crucial | Preserve forensic state for investigation. |
| Future automation | Implement Logic Apps for auto-blocking IPs. |

**Notes:**
- Sentinel alerts effective → Alerts triggered in Sentinel analytics rules.
- Cloud Shell useful → Verified when you blocked attacker IPs using az network nsg rule create.
- Snapshots crucial → You created VM snapshots in Azure Portal → Disks → Snapshots.
- Future automation → Suggest Logic Apps for auto-blocking IPs in future deployments.

## 6. Logs & Observations

### 6.1 VM Event Logs

| Event ID | Description | Observation |
|----------|-------------|-------------|
| 4624 | Successful logon | labuser login verified |
| 4625 | Failed logon | ~500+ failed RDP attempts |
| 4672 | Privileged access | Admin logon event |

<p align="center">
 <br/>
<img src="https://imgur.com/fMlFFbl.png" alt="attack_map"/>
<br />
</p>

### 6.2 Overall Assessment

#### SOC Honeypot VM Forensics – Process Scan Conclusion

**No Active Malware Found**

- All processes running on the VM are legitimate Windows or Azure system processes.
- No unknown or suspicious .exe processes were found running in memory.

**Azure Guest Agent Processes Normal**

- Processes like WaAppAgent.exe, WindowsAzureGuestAgent.exe, and WaSecAgentProv.exe are standard on Azure VMs.
- No malware disguised as Azure agents was detected.

**No Suspicious User-Level Activity Detected in Memory**

- No rogue powershell.exe or unauthorized scripts appear to be running at the time of the scan.
- The VM does not show active malicious processes, which is a positive sign.
- Past attacks may have attempted login or downloaded scripts, but no active persistence or running malware is detected.

<p align="center">
 <br/>
<img src="https://imgur.com/QC7cEwh.png" alt="attack_map"/>
<br />
</p>

## 7. Mitigation Actions Summary

| Action | Description | Status |
|--------|-------------|--------|
| NSG Rule Added | Blocked attacker IP 105.245.20.121, 102.213.28.196, 35.195.43.11, 102.213.28.196 | Completed |
| Snapshot Created | OS disk preserved for forensic analysis | Completed |
| VM Isolated | Disconnected from network | Completed |
| Credentials Rotated | Reset all admin passwords | Completed |
| Defender Enabled | Microsoft Defender for Servers activated | Completed |
| Sentinel Alert Rule | "Brute Force Detection" analytics rule | Completed |
| Network Hardened | Allowed RDP only from SOC subnet | Completed |

## 8. Conclusion

The SOC Honeypot project demonstrated practical cloud security monitoring, incident response, and forensic investigation using Microsoft Azure. Key outcomes and lessons include:

**Threat Observation:**

- Deployed a vulnerable Windows 11 pro VM to attract real-world attacks.
- Monitored multiple unauthorized login attempts via RDP (Event ID 4624, 4625).
- Observed suspicious activity including potential malicious scripts and binaries.

**Containment & Mitigation:**

- Blocked attacker IPs using Azure NSG rules.
- Isolated the compromised VM from the network.
- Preserved OS disk snapshots for forensic analysis.
- Enabled Microsoft Defender for Servers and created Sentinel alert rules for brute-force detection.

**Forensic Investigation:**

- Collected PowerShell history, VM event logs, and system binaries.
- Verified that no persistent malicious processes remained in memory.

**Key Lessons Learned:**

- Exposed RDP ports are high-risk; JIT access and NSG restrictions are essential.
- Automated alerts effectively detect brute-force attempts.
- Snapshots and Cloud Shell simplify containment and preserve evidence.
- Future automation with Logic Apps can enable auto-blocking of attacker IPs.

**Overall:**

This project highlights the importance of proactive cloud security monitoring, rapid containment, and thorough forensic analysis. The integration of Azure security tools ensures both resilience against attacks and actionable insights for incident response.

