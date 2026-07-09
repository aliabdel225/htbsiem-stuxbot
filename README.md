Hunting for Stuxbot (Round 2)
Threat Hunting Investigation using Elastic SIEM








Overview

This investigation was completed as part of a threat hunting exercise using the Elastic Stack SIEM.

The objective was to investigate the latest operational behavior of the Stuxbot malware family after new intelligence suggested changes in its attack methodology.

The threat intelligence indicated that newer variants of Stuxbot now perform three major actions during compromise:

Transfer hacking tools into C:\Users\Public
Establish persistence through Registry Run Keys
Move laterally using PowerShell Remoting

The goal was to validate each behavior using Windows event logs, Sysmon logs, and PowerShell Script Block Logging.

Lab Environment

SIEM

Elastic Stack (Discover)

Available Logs

Windows Event Logs
Sysmon Logs
PowerShell Logs
Zeek Network Logs
Threat Intelligence

Before beginning any hunt, it is important to understand what intelligence tells us to look for.

Recent intelligence stated that Stuxbot now:

Copies tools into C:\Users\Public
Creates Registry Run Keys to survive reboots
Uses PowerShell Remoting to access Domain Controllers

Instead of randomly searching logs, we build our hunting queries around these known attacker behaviors.

MITRE ATT&CK Mapping
Technique	MITRE ID	Purpose
Lateral Tool Transfer	T1570	Move attacker tools between compromised systems
Registry Run Keys	T1547.001	Maintain persistence after reboot
PowerShell Remoting	T1021.006	Lateral movement to remote systems
Hunt 1 — Lateral Tool Transfer (MITRE T1570)
Objective

Determine whether Stuxbot copied tools into the C:\Users\Public directory.

Why C:\Users\Public?

Attackers commonly abuse this folder because:

Every user can access it
It usually has write permissions
Files stored here rarely attract attention
Security products often ignore legitimate software stored here

Instead of placing tools inside Program Files or Windows directories, attackers frequently stage payloads inside Users\Public.

Hunting Query
event.code:11 AND message:"*\\Users\\Public\\*"
Why use message:?

This is one of the most important concepts in threat hunting.

Sysmon Event ID 11 logs File Creation events.

Although the event contains structured fields like:

file.path
process.name

the message field contains the complete human-readable event.

Searching:

message:"*\Users\Public\*"

tells Kibana:

Search every File Creation event and return only those whose event message contains the path C:\Users\Public.

Instead of searching every file created on every system, we immediately narrow the hunt to the exact directory mentioned in the threat intelligence.

This dramatically reduces noise.

Evidence

(Insert Screenshot 1 – MITRE ATT&CK T1570)

(Insert Screenshot 2 – Kibana Query)

(Insert Screenshot 3 – Search Results)

Findings

The query returned 7 File Creation events inside:

C:\Users\Public

Several files immediately stood out.

Suspicious Files
mimikatz.exe

Credential dumping tool.

Used to extract:

Passwords
Kerberos Tickets
NTLM Hashes
Rubeus.exe

Kerberos attack framework.

Commonly used for:

Kerberoasting
Pass-the-Ticket
Ticket Forgery
Invoke-DCSync.ps1

PowerShell script that performs a DCSync attack.

Allows attackers to request password hashes directly from a Domain Controller without logging into it interactively.

SharpHound.exe

BloodHound data collector.

Maps:

Active Directory
Privileges
Trust relationships
Attack paths
DomainPasswordSpray.ps1

Password spraying tool.

Attempts one password across many accounts to avoid account lockouts.

payload.exe

Likely the malware payload delivered during the attack.

User Responsible

The transferred tool beginning with the letter R was:

Rubeus.exe

The associated user was:

svc-sql1

This strongly suggests that the compromised SQL service account was used during lateral movement.

Why This Matters

This stage demonstrates the attacker preparing additional tools after gaining initial access.

Rather than downloading tools every time they are needed, attackers often stage everything locally before continuing the attack.

This is a classic example of MITRE ATT&CK T1570 — Lateral Tool Transfer.

Hunt 2 — Registry Run Keys (MITRE T1547.001)
Objective

Determine whether Stuxbot established persistence through Registry Run Keys.

What is Persistence?

Persistence means:

If the victim reboots, the malware automatically starts again.

Without persistence, an attacker may lose access after a restart.

Registry Run Keys are one of the oldest and most common persistence techniques on Windows.

Common Registry Run Keys
HKCU\Software\Microsoft\Windows\CurrentVersion\Run
HKLM\Software\Microsoft\Windows\CurrentVersion\Run

Any executable referenced here launches automatically whenever a user logs in.

Hunting Query
event.code:13 AND message:"*\\Run\\*"
Why Event ID 13?

Sysmon Event ID 13 records:

Registry Value Set

This means:

Someone created or modified a registry value.

Exactly what we expect when malware installs persistence.

Why Search message?

Again, the message field contains the full registry path.

Searching:

*\Run\*

returns every registry modification involving Run Keys.

This quickly isolates persistence-related events from thousands of unrelated registry modifications.

Fields Added

To better understand the event, two additional fields were added:

registry.path

Shows:

Where the registry value was created.

Example:

HKU\...\Software\Microsoft\Windows\CurrentVersion\Run
registry.value

Shows:

The actual value name created.

This is often:

malware
updater
random characters
Evidence

(Insert Screenshot 4 – MITRE ATT&CK Persistence)

(Insert Screenshot 5 – Query)

(Insert Screenshot 6 – Registry Results)

Findings

The first suspicious Run Key created was:

LgvHsviAUVTsIN

Unlike legitimate software names such as:

OneDrive
Adobe
Teams

this registry value appears completely random.

Randomized registry values are a common malware technique used to evade detection and make analysis more difficult.

Why This Matters

This confirms that Stuxbot successfully installed persistence.

Now, even if the victim restarts the computer, Windows automatically launches the malware.

Without detecting and removing this Run Key, simply deleting the malware executable would not completely remove the infection.

Hunt 3 — PowerShell Remoting (MITRE T1021.006)
What is PowerShell Remoting?

PowerShell Remoting allows administrators to execute PowerShell commands on remote Windows computers.

Administrators commonly use it to:

Manage servers
Install software
Run scripts
Configure Domain Controllers

Unfortunately, attackers abuse the exact same feature.

Instead of logging into every computer manually, they execute commands remotely across the network.

This allows malware to spread rapidly while blending in with legitimate administrative activity.

Why Attackers Love PowerShell Remoting

PowerShell Remoting provides:

Remote code execution
Credential reuse
Administrative control
Encrypted communication
Native Windows functionality

Because it is built into Windows, many organizations allow it through firewalls.

Hunting Query
event.code:4104 AND powershell.file.script_block_text:*PSSession*
Why Event ID 4104?

PowerShell Script Block Logging records every PowerShell command executed.

Instead of only recording:

powershell.exe

it records the actual PowerShell code.

This makes Event ID 4104 one of the most valuable log sources for detecting malicious PowerShell activity.

Why Search for PSSession?

PowerShell Remoting relies on:

New-PSSession
Enter-PSSession
Invoke-Command

Searching for:

PSSession

captures PowerShell remoting activity regardless of the specific command used.

Evidence

(Insert Screenshot 7 – Query)

(Insert Screenshot 8 – Script Block Results)

Findings

One script block clearly shows:

Enter-PSSession dc1

This indicates that the attacker initiated a remote PowerShell session with:

DC1

The Domain Controller.

The associated user responsible for the activity was:

svc-sql1

This confirms that the compromised service account was later used to remotely access the Domain Controller.

Why This Matters

This represents the most critical phase of the attack.

Compromising a workstation is serious.

Compromising a Domain Controller is catastrophic.

Once attackers gain access to the Domain Controller they can:

Dump every Active Directory password hash
Create new administrator accounts
Deploy malware to every computer
Control the entire Windows domain

PowerShell Remoting provided the mechanism for that lateral movement.

Overall Attack Timeline
Initial Compromise
        │
        ▼
Tools copied into C:\Users\Public
        │
        ▼
Persistence installed via Registry Run Keys
        │
        ▼
PowerShell Remoting initiated
        │
        ▼
Remote access to DC1
        │
        ▼
Potential Active Directory compromise
Key Indicators of Compromise (IOCs)
IOC	Description
C:\Users\Public\mimikatz.exe	Credential dumping
C:\Users\Public\Rubeus.exe	Kerberos attacks
C:\Users\Public\SharpHound.exe	AD enumeration
Invoke-DCSync.ps1	Active Directory hash extraction
DomainPasswordSpray.ps1	Password spraying
Random Registry Run Key	Persistence
Enter-PSSession dc1	PowerShell Remoting
svc-sql1	Compromised service account
Conclusion

This investigation successfully validated all three behaviors described in the threat intelligence. Using Elastic SIEM and targeted KQL queries, evidence showed that the attacker transferred offensive tools into C:\Users\Public, established persistence through Registry Run Keys, and later leveraged PowerShell Remoting to move laterally toward the Domain Controller. The presence of tools such as Mimikatz, Rubeus, SharpHound, and Invoke-DCSync, combined with the suspicious Run Key and the Enter-PSSession dc1 command, demonstrates a realistic post-exploitation attack chain commonly seen during Active Directory compromises. By correlating Sysmon and PowerShell logs with MITRE ATT&CK techniques, this investigation illustrates how defenders can move from threat intelligence to evidence-based hunting and identify attacker activity before it results in full domain compromise.

Acknowledgements
Hack The Box Academy – Threat Hunting: Hunting for Stuxbot (Round 2)
MITRE ATT&CK Framework – Technique mapping and adversary behaviors
Elastic Stack – SIEM platform used for log analysis
Microsoft Sysmon – Endpoint telemetry and event logging
