# FTP Log Analysis Using Splunk

## Objective
Analyze FTP log files using Splunk to monitor file transfer activity, detect anomalies, identify suspicious usernames, commands, and file transfers that may indicate a security threat.

## Tools Used
- Splunk Enterprise 10.2.0 (local instance)
- Sample FTP log file (secrepo.com - MACCDC 2012 dataset)

## MITRE ATT&CK Mapping
| Technique | ID | Tactic |
|---|---|---|
| Exfiltration Over Alternative Protocol | T1048.003 | Exfiltration |
| Ingress Tool Transfer | T1105 | Command and Control |
| Valid Accounts | T1078 | Defense Evasion, Persistence |

---

## Setup

### Log File
- Source: secrepo.com sample FTP log (ftp.log.gz)
- Format: Zeek/Bro tab-separated log
- Fields present: timestamp, uid, src_ip, src_port, dest_ip, dest_port, user, password, command, arg, mime_type, file_size, reply_code, reply_msg

### Splunk Configuration
- Index used: `ftp_logs`
- Source type: `ftp_logs1`

### Setup Notes
- Same MACCDC 2012 dataset as the DNS project
- Timestamp format set to `%s` (Unix epoch) under Advanced timestamp settings
- `MAX_DAYS_AGO` set to `6000` to allow indexing of 2012 events
- Fields not auto-extracted. All structured queries use rex for field extraction

---

## Tasks and Findings

### Task 1: Upload and Verify FTP Logs

**Steps taken:**
1. Navigated to Settings > Add Data > Upload
2. Selected ftp.log file
3. Set timestamp format to `%s` and MAX_DAYS_AGO to `6000`
4. Saved source type as `ftp_logs1`
5. Selected `ftp_logs` as the index
6. Ran verification query after upload

**Query used:**
```spl
index=ftp_logs sourcetype=ftp_logs1
```

**Screenshot:**
> <img width="1897" height="907" alt="image" src="https://github.com/user-attachments/assets/642ed17b-8629-4a97-a5db-6edad14e1756" />


**Finding:**
> [How many events were ingested? What time range do the logs cover?]

---

### Task 2: Search for FTP Events

**Query used:**
```spl
index=ftp_logs sourcetype=ftp_logs1
```

**Screenshot:**
> <img width="1897" height="907" alt="image" src="https://github.com/user-attachments/assets/1df3b88e-3bbe-4eff-8225-25ea04ece6cf" />


**Finding:**
> [How many events returned? What fields are visible in the raw events?]

---

### Task 3: Analyze File Transfer Activity

**Query used:**
```spl
index=ftp_logs sourcetype=ftp_logs1 | rex field=_raw "^\S+\s+\S+\s+(?P<src_ip>\S+)\s+\S+\s+\S+\s+\S+\s+(?P<user>\S+)\s+\S+\s+(?P<command>\S+)\s+(?P<arg>\S+)" | stats count by command | sort -count
```

**Screenshot:**
> <img width="1895" height="899" alt="image" src="https://github.com/user-attachments/assets/d923ca98-47f9-4f81-ad09-d373c6fe89ab" />


**Finding:**
> [Which FTP commands appeared most frequently? What does that tell you about the activity?]

---

### Task 4: Detect Anomalies

**Query used:**
```spl
index=ftp_logs sourcetype=ftp_logs1 | rex field=_raw "^\S+\s+\S+\s+(?P<src_ip>\S+)\s+\S+\s+\S+\s+\S+\s+(?P<user>\S+)\s+(?P<password>\S+)\s+(?P<command>\S+)\s+(?P<arg>\S+)" | stats count by user password | sort -count
```

**Screenshot:**
> <img width="1894" height="899" alt="image" src="https://github.com/user-attachments/assets/281156cc-6f80-49e7-b186-0ae5039bc980" />


**Finding:**
> [What usernames and passwords were used? Were there anonymous logins? Were there weak credentials?]

---

### Task 5: Monitor User Behavior

**Query used:**
```spl
index=ftp_logs sourcetype=ftp_logs1 | rex field=_raw "^\S+\s+\S+\s+(?P<src_ip>\S+)\s+\S+\s+\S+\s+\S+\s+(?P<user>\S+)\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(?P<reply_code>\S+)" | stats count by src_ip user reply_code | sort -count
```

**Screenshot:**
> <img width="1901" height="899" alt="image" src="https://github.com/user-attachments/assets/25497ed5-4e0d-4a1f-a13b-841675a2c969" />


**Finding:**
> [Which IPs had the most activity? Were there failed login attempts (reply code 530)? Any successful anonymous logins (reply code 230)?]

---

### Task 6: Investigate Suspicious File Transfers

**Query used:**
```spl
index=ftp_logs sourcetype=ftp_logs1 | rex field=_raw "^\S+\s+\S+\s+(?P<src_ip>\S+)\s+\S+\s+\S+\s+\S+\s+(?P<user>\S+)\s+\S+\s+(?P<command>\S+)\s+(?P<arg>\S+)\s+(?P<mime_type>\S+)\s+(?P<file_size>\S+)" | search command=RETR OR command=STOR | table src_ip user command arg mime_type file_size
```

**Screenshot:**
> [Insert screenshot of file transfer results]

**Finding:**
> [What files were transferred? Were any executables or suspicious file types transferred? Any transfers to external IPs?]

---

## Summary of Findings

| Task | Key Finding |
|---|---|
| Log Upload | [summary] |
| FTP Event Search | [summary] |
| File Transfer Activity | [summary] |
| Anomaly Detection | [summary] |
| User Behavior | [summary] |
| Suspicious File Transfers | [summary] |

---

## Key Takeaways
> [Write 2 to 3 sentences after completing the project. What did you learn? What would you do differently in a real SOC environment?]

---

*Part of the SOC Skills Roadmap | Project 1: Splunk*
