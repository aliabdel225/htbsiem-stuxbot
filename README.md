# Hunting for Stuxbot
## Threat Hunting Investigation using Elastic SIEM

![MITRE](https://img.shields.io/badge/MITRE-ATT%26CK-red)
![Elastic](https://img.shields.io/badge/SIEM-Elastic-blue)
![Status](https://img.shields.io/badge/Status-Completed-success)
![Platform](https://img.shields.io/badge/Platform-Hack%20The%20Box-green)

---

# Executive Summary

This repository documents a complete threat hunting investigation performed in Elastic SIEM against a simulated enterprise environment infected with the latest iteration of **Stuxbot**.

The objective was to validate three intelligence reports:

1. Lateral Tool Transfer to `C:\Users\Public`
2. Registry Run Key persistence
3. PowerShell Remoting used for lateral movement toward a Domain Controller

The investigation was performed using Windows Event Logs, Sysmon, and PowerShell Script Block Logging while mapping activity to the MITRE ATT&CK Framework.

---

# Repository Structure

```text
.
├── README.md
├── Screenshots/
│   ├── hunt1/
│   ├── hunt2/
│   └── hunt3/
├── Queries/
│   └── KQL_Queries.md
├── Reports/
│   └── Stuxbot_Investigation.pdf
└── LICENSE
```

---

# Lab Environment

**SIEM**
- Elastic Stack (Discover)

**Data Sources**
- Windows Event Logs
- Sysmon
- PowerShell Logs
- Zeek

---

# MITRE ATT&CK Mapping

| Technique | MITRE ID |
|-----------|-----------|
| Lateral Tool Transfer | T1570 |
| Registry Run Keys | T1547.001 |
| PowerShell Remoting | T1021.006 |

---

# Hunt 1 – Lateral Tool Transfer

## Objective

Determine whether Stuxbot staged tools inside `C:\Users\Public`.

### KQL

```kql
event.code:11 AND message:"*\\Users\\Public\\*"
```

### Why Event ID 11?

Sysmon Event ID 11 records file creation events.

### Why search the `message` field?

The `message` field contains the complete event details in human-readable format, including the full file path. Searching for:

```text
*\Users\Public\*
```

filters all file creation events down to files created inside the directory identified in the threat intelligence.

### Findings

The investigation identified several offensive security tools:

- Mimikatz
- Rubeus
- SharpHound
- Invoke-DCSync.ps1
- DomainPasswordSpray.ps1
- payload.exe

The transferred tool beginning with **R** was **Rubeus.exe**, created under the **svc-sql1** account.

**Insert screenshots here**
- `Screenshots/hunt1/01-query.png`
- `Screenshots/hunt1/02-results.png`
- `Screenshots/hunt1/03-tools.png`

---

# Hunt 2 – Registry Run Keys

## Objective

Identify persistence using Windows Registry Run Keys.

### KQL

```kql
event.code:13 AND message:"*\\Run\\*"
```

### Why Event ID 13?

Sysmon Event ID 13 records Registry Value Set events.

### Why search `message`?

The message field contains the registry path. Searching for `\\Run\\` isolates registry modifications affecting Windows Run Keys.

### Additional Fields

- `registry.path`
- `registry.value`

### Findings

The first suspicious registry value discovered was:

```
LgvHsviAUVTsIN
```

The randomly generated value name strongly suggests malware persistence rather than legitimate software.

**Insert screenshots here**
- `Screenshots/hunt2/01-query.png`
- `Screenshots/hunt2/02-results.png`
- `Screenshots/hunt2/03-first-persistence.png`

---

# Hunt 3 – PowerShell Remoting

## What is PowerShell Remoting?

PowerShell Remoting allows administrators to execute commands remotely using WinRM. While legitimate for administration, attackers abuse it to execute commands across multiple systems and move laterally without interactive logons.

### KQL

```kql
event.code:4104 AND powershell.file.script_block_text:*PSSession*
```

### Why Event ID 4104?

PowerShell Script Block Logging records the actual PowerShell code executed, making it invaluable for threat hunting.

### Findings

The script block contained:

```
Enter-PSSession dc1
```

This indicates the attacker initiated a remote PowerShell session to **DC1**, using the compromised **svc-sql1** account.

**Insert screenshots here**
- `Screenshots/hunt3/01-query.png`
- `Screenshots/hunt3/02-scriptblock.png`

---

# Attack Chain

```text
Initial Compromise
      │
      ▼
Compromise of svc-sql1
      │
      ▼
Copy Tools into C:\Users\Public
      │
      ▼
Registry Run Key Created
      │
      ▼
PowerShell Remoting
      │
      ▼
Domain Controller (DC1)
```

---

# Incident Response

## Containment

- Isolate infected host
- Disable `svc-sql1`
- Block WinRM
- Preserve forensic evidence
- Prevent DC communication

## Eradication

- Remove all malicious files from `C:\Users\Public`
- Delete malicious Run Key
- Reset compromised credentials
- Investigate Domain Controller for DCSync activity

## Recovery

- Restore from clean backups if required
- Verify persistence has been removed
- Monitor Event IDs 11, 13, and 4104
- Validate no attacker access remains

## Lessons Learned

- Enable Sysmon on all Windows endpoints
- Enable PowerShell Script Block Logging
- Restrict WinRM
- Monitor Run Key modifications
- Alert on offensive tooling (Mimikatz, Rubeus, SharpHound)
- Apply least privilege to service accounts

---

# Indicators of Compromise

| IOC | Purpose |
|------|---------|
| Mimikatz.exe | Credential dumping |
| Rubeus.exe | Kerberos abuse |
| SharpHound.exe | Active Directory enumeration |
| Invoke-DCSync.ps1 | Password hash replication |
| DomainPasswordSpray.ps1 | Password spraying |
| LgvHsviAUVTsIN | Registry persistence |
| Enter-PSSession dc1 | Lateral movement |

---

# Conclusion

This investigation successfully validated all three threat intelligence indicators. Evidence showed that Stuxbot staged offensive tools in `C:\Users\Public`, established persistence through Registry Run Keys, and used PowerShell Remoting to move laterally toward the Domain Controller. The activity closely aligns with MITRE ATT&CK techniques T1570, T1547.001, and T1021.006, demonstrating a realistic post-exploitation attack chain and highlighting how defenders can leverage Elastic SIEM and KQL to detect and investigate sophisticated adversary behavior.

---

# Acknowledgements

- Hack The Box Academy
- MITRE ATT&CK
- Elastic Stack
- Microsoft Sysmon
