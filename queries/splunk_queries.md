# Splunk Threat Hunting & Detection Queries

This document contains all Splunk SPL queries developed during the SOC Threat Hunting Lab.

These queries are designed for detection engineering, threat hunting, and investigation workflows.

---

## 1. PowerShell Execution Detection

**Objective:** Identify PowerShell usage across the environment

```
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| search Image="*powershell.exe"
| stats count by host Image
```

## 2. Encoded PowerShell Command Detection

Objective: Detect obfuscated PowerShell commands

```
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
| search CommandLine="EncodedCommand"
| stats count by host CommandLine
```

---

## 3. Parent-Child Process Analysis

Objective: Identify suspicious process relationships
```
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]+)</Data>"
| stats count by ParentImage Image
| sort -count
```

---

## 4. LSASS Access Detection

Objective: Detect credential dumping attempts

```
index=* EventCode=10
| rex field=_raw "<Data Name='TargetImage'>(?<TargetImage>[^<]+)</Data>"
| rex field=_raw "<Data Name='SourceImage'>(?<SourceImage>[^<]+)</Data>"
| search TargetImage="*lsass.exe"
| stats count by SourceImage TargetImage
```

## 5. SSH Brute Force Detection

Objective: Identify failed SSH login attempts

```
index=* "Failed password"
| rex field=_raw "from\s(?<src_ip>\d{1,3}(\.\d{1,3}){3})"
| where src_ip!="127.0.0.1"
| stats count by src_ip
| sort -count
```

## 6. Detection Volume (Time-Based)

```
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| timechart span=1h count
```

## 7. Simulation 2 — Encoded PowerShell Command

**Command**
```
powershell -EncodedCommand UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgAGMAYQBsAGMALgBlAHgAZQA=
```

## 8. Simulation 3 — Suspicious Process Execution

**Command**
```
powershell Start-Process calc.exe
```


## 9. Field Extraction Query
```
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]+)</Data>"
| head 20
```

## 10. Example Sigma Rule

```yaml
title: Suspicious PowerShell Encoded Command
logsource:
  product: windows
  service: sysmon

detection:
  selection:
    EventID: 1
    Image|endswith: '\powershell.exe'
    CommandLine|contains:
      - '-EncodedCommand'
      - '-enc'

condition: selection
level: high
```
## 11. Detection Query
```
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
| search Image="*powershell.exe" AND CommandLine="*EncodedCommand*"
| stats count by host CommandLine
```

## 12.1. Suspicious PowerShell Execution

**Objective**

Identify PowerShell usage across the environment to detect potential abuse.

**Splunk Query**

```
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| search Image="*powershell.exe"
| stats count by host Image

```

## 12.2 Encoded PowerShell Command Detection

**Objective**

Detect obfuscated PowerShell commands used to evade detection.

**Splunk Query**

```
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
| search CommandLine="EncodedCommand"
| stats count by host CommandLine

```

## 12.3 Suspicious Parent-Child Process Relationship

**Objective**

Identify abnormal process spawning behavior.

**Splunk Query**

```
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]+)</Data>"
| search ParentImage="*powershell.exe"
| stats count by ParentImage Image

```

## 12.4 LSASS Access Detection (Credential Dumping)

**Objective**

Detect processes attempting to access LSASS memory.

**Splunk Query**

```
index=* EventCode=10
| rex field=_raw "<Data Name='TargetImage'>(?<TargetImage>[^<]+)</Data>"
| rex field=_raw "<Data Name='SourceImage'>(?<SourceImage>[^<]+)</Data>"
| search TargetImage="*lsass.exe"
| stats count by SourceImage TargetImage
```

## 12.5 Process Enumeration Activity

**Objective**

Detect commands used for system discovery.

**Splunk Query**
```
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
| search CommandLine="Get-Process"
| stats count by CommandLine
```

## 13.1 Step 2 — Initial Triage

Validate whether the alert is a false positive or requires investigation.

Key checks:

- Frequency of occurrence
- Host involved
- Time of execution
- User context (if available)

Splunk Query:

```spl
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]+)</Data>"
| search CommandLine="*EncodedCommand*"
| table _time host Image ParentImage CommandLine
| sort -_time

```

## 13.2 Step 3 — Process Analysis

Understand process behavior and relationships.

Questions:

- What launched the process?
- Is the parent process legitimate?
- Is PowerShell spawned from unusual locations?

Example Query:
```
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]+)</Data>"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
| table _time Image ParentImage CommandLine
| sort -_time
```

## 13.3 Step 4 — Parent-Child Relationship Analysis

Identify suspicious process chains.

Examples:

winword.exe → powershell.exe
explorer.exe → cmd.exe → powershell.exe

Query:

```
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]+)</Data>"
| where isnotnull(ParentImage)
| stats count by ParentImage Image
| sort -count
```
## 13.4 Step 5 — Command Line Inspection

Analyze command-line arguments for:

- Encoded commands
- Obfuscation
- Suspicious flags


Query:
```
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
| search CommandLine="*EncodedCommand*"
| table _time host CommandLine
| sort -_time
```

## 13.5 Step 6 — Timeline Analysis

Reconstruct attacker activity timeline.

This helps identify bursts of suspicious activity and correlate execution patterns over time.

Query:

```
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
| search CommandLine="*EncodedCommand*"
| timechart count
```

```
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
| search CommandLine="*EncodedCommand*"
| timechart span=1h count
```

## 14 Use Case — SSH Brute Force Detection

Fail2Ban was configured on the Linux (Splunk) server to monitor authentication logs.

When multiple failed login attempts are detected:

- The source IP is automatically banned
- Firewall rules are updated dynamically

---

## Configuration File

Location:
```
/etc/fail2ban/jail.local
```
Example configuration:

```
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 600
findtime = 600
```

## 15 Verification

The following command was used to verify that the SSH protection mechanism was active and enforcing bans.

Check Fail2Ban status:

```
sudo fail2ban-client status sshd
```
Example output:

```
Status for the jail: sshd
|- Filter
|  |- Currently failed: 0
|  |- Total failed: 5
|  `- File list: /var/log/auth.log
`- Actions
   |- Currently banned: 1
   |- Total banned: 1
   `- Banned IP list: 192.168.1.100
```


## 16.1 Issue 1 — Sysmon Not Recognized in PowerShell

### Problem

The command

 ```
 sysmon -c sysmonconfig.xml
 ``` 
 
 failed with: "sysmon is not recognized as the name of a cmdlet"

 ### Resolution

- Navigated to the Sysmon installation directory
- Executed Sysmon using full path:

```
C:\Tools\Sysmon64.exe -c C:\Tools\sysmonconfig.xml

```

## 16.2 Issue 2 — No Logs Appearing in Splunk

### Problem

Splunk queries returned no results for Sysmon logs.

### Root Cause

- Sysmon logs were not being forwarded
- Incorrect sourcetype or index configuration

### Resolution

- Verified Splunk Universal Forwarder configuration
- Confirmed log source:

```
WinEventLog:Microsoft-Windows-Sysmon/Operational
```

- Restarted Splunk services



## 16.3 Issue 3 — Fields Not Extracted (Image, CommandLine, ParentImage)

### Problem

Fields such as Image and CommandLine were not visible in Splunk.

### Root Cause

- Sysmon logs stored in XML format
- Fields not automatically parsed

### Resolution

- Used rex extraction:

```
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
```


- Applied consistent extraction across all queries


## 16.4 Issue 5 — Fail2Ban Not Installed

### Problem

Command `fail2ban-client` not found.

### Root Cause

- Fail2Ban package not installed on Ubuntu

### Resolution

```
sudo apt update
sudo apt install fail2ban -y
```


## 16.5 Issue 6 — SSH Attack Not Detected

### Problem

Fail2Ban did not trigger bans.

### Root Cause

- Incorrect IP targeting
- Network connectivity issues between VMs

### Resolution

- Identified correct Ubuntu IP using:

```
ip a
```

- Verified connectivity
- Generated multiple failed SSH login attempts

## 16.6 Issue 7 — Incorrect Command Usage

### Problem

Command failed due to syntax error:

```
cd..
```

### Root Cause

- Missing space in Linux command

### Resolution

```
cd .. or cd /
```


## 16.7 Issue 8 — Service Command Typo

### Problem
```
systemctl: command not found
```

### Root Cause

- Typo in command (`systemct1` instead of `systemctl`)

### Resolution

Corrected command:
```
sudo systemctl start fail2ban
```


## 17.1 Detection Volume

Measures the volume of detection events over time.

**Purpose:**

- Identify spikes in suspicious activity
- Detect abnormal behavior patterns

**Splunk Query:**
```
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| timechart span=1h count
```


## 17.2 Top Triggered Detections

Identifies the most frequently triggered detection rules.

**Purpose:**

- Highlight common attack techniques
- Identify noisy detections

**Splunk Query:**

```
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<Data Name='CommandLine'>(?<CommandLine>[^<]+)</Data>"
| eval DetectionType=case(
like(CommandLine,"%EncodedCommand%"),"Encoded PowerShell",
like(CommandLine,"%ExecutionPolicy Bypass%"),"Execution Policy Bypass"
)
| where isnotnull(DetectionType)
| stats count by DetectionType
| sort -count
```

## 17.3 Suspicious Process Frequency

Tracks frequently executed suspicious processes.

**Purpose:**

- Identify repeated attacker behavior
- Detect persistence or automation

**Splunk Query:**
```
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| stats count by Image
| sort -count
```

## 17.4 Parent-Child Process Anomalies

Analyzes unusual process relationships.

**Purpose:**

- Detect suspicious execution chains
- Identify lateral movement or scripting activity

**Splunk Query:**
```
index=* sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
| rex field=_raw "<Data Name='Image'>(?<Image>[^<]+)</Data>"
| rex field=_raw "<Data Name='ParentImage'>(?<ParentImage>[^<]+)</Data>"
| stats count by ParentImage Image
| sort -count
```

## 17.5 Failed Authentication Attempts (Fail2Ban Correlation)

Tracks failed SSH login attempts and banned IPs.

**Purpose:**

- Measure brute force attempts
- Validate automated defense effectiveness

**Splunk Query:**
```
index=* "Failed password"
| rex field=_raw "from\s(?<src_ip>\d{1,3}(\.\d{1,3}){3})"
| where src_ip!="127.0.0.1"
| stats count by src_ip
| sort -count
```