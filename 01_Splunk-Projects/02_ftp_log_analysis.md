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
5,796 events successfully ingested. Timestamps correctly reflect March 2012 dates after applying the Unix epoch timestamp fix. Log covers FTP activity from the MACCDC 2012 competition environment. Fields are not automatically extracted by Splunk due to the Zeek log format, requiring rex-based extraction for all structured analysis.

---

### Task 2: Search for FTP Events

**Query used:**
```spl
index=ftp_logs sourcetype=ftp_logs1
```

**Screenshot:**
> <img width="1897" height="907" alt="image" src="https://github.com/user-attachments/assets/1df3b88e-3bbe-4eff-8225-25ea04ece6cf" />

**Finding:**
5,796 events returned. Raw events confirmed the Zeek FTP log structure with tab-separated fields including timestamp, uid, source IP, source port, destination IP, destination port, username, password, FTP command, argument, mime type, file size, reply code and reply message. First visible event showed an APPE command with binary hex data in the argument field, indicating suspicious file append activity from the start of the dataset.

---

### Task 3: Analyze File Transfer Activity

**Query used:**
```spl
index=ftp_logs sourcetype=ftp_logs1 | rex field=_raw "^\S+\s+\S+\s+(?P<src_ip>\S+)\s+\S+\s+\S+\s+\S+\s+(?P<user>\S+)\s+\S+\s+(?P<command>\S+)\s+(?P<arg>\S+)" | stats count by command | sort -count
```

**Screenshot:**
> <img width="1895" height="899" alt="image" src="https://github.com/user-attachments/assets/d923ca98-47f9-4f81-ad09-d373c6fe89ab" />

**Finding:**
6 unique FTP commands identified across 5,796 events:

| Command | Count | Meaning | Assessment |
|---|---|---|---|
| PASV | 2,830 | Passive mode request | Normal. Standard FTP data connection setup. |
| STOR | 1,353 | Upload file to server | Suspicious. Very high upload volume. |
| DELE | 1,351 | Delete file from server | Critical. Almost exactly matching STOR count. Upload then delete pattern. |
| RETR | 112 | Download file from server | Notable. Contains executable downloads. |
| PORT | 78 | Active mode data connection | Normal. |
| APPE | 72 | Append data to file | Suspicious. Binary hex data observed in append arguments. |

STOR at 1,353 and DELE at 1,351 almost perfectly matching is the most significant pattern. Someone uploaded files and then deleted them immediately. This is consistent with malware staging, cover track behaviour, or automated attack tooling.

---

### Task 4: Detect Anomalies

**Query used:**
```spl
index=ftp_logs sourcetype=ftp_logs1 | rex field=_raw "^\S+\s+\S+\s+(?P<src_ip>\S+)\s+\S+\s+\S+\s+\S+\s+(?P<user>\S+)\s+(?P<password>\S+)\s+(?P<command>\S+)\s+(?P<arg>\S+)" | stats count by user password | sort -count
```

**Screenshot:**
> <img width="1894" height="899" alt="image" src="https://github.com/user-attachments/assets/281156cc-6f80-49e7-b186-0ae5039bc980" />

**Finding:**
14 unique username and password combinations identified. Key findings:

| User | Password | Count | Assessment |
|---|---|---|---|
| ftp | password@example.com | 5,404 | Default anonymous FTP credential. Dominant activity in dataset. |
| anonymous | password | 189 | No real authentication. |
| anonymous | justinwray@justinwray.com | 44 | Anonymous login with real email. |
| anonymous | IEUser@ | 31 | Internet Explorer default FTP password. Automated browser traffic. |
| ftp | password | 10 | Weakest possible credential. Source of svchost.exe download. |
| anonymous | test | 7 | Weak test credential. |
| anonymous | anon@lulz.com | 5 | lulz.com associated with hacker culture. Notable. |
| spatiald | hidden | 2 | Only non-anonymous real username. Password redacted by Zeek. |

Almost all FTP activity uses anonymous or default credentials. The server is either a public FTP server or severely misconfigured. The `ftp`/`password` combination is directly linked to the svchost.exe malware distribution discovered in Task 6.

---

### Task 5: Monitor User Behavior

**Query used:**
```spl
index=ftp_logs sourcetype=ftp_logs1 | rex field=_raw "^\S+\s+\S+\s+(?P<src_ip>\S+)\s+\S+\s+\S+\s+\S+\s+(?P<user>\S+)\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(?P<reply_code>\S+)" | stats count by src_ip user reply_code | sort -count
```

**Screenshot:**
> <img width="1901" height="899" alt="image" src="https://github.com/user-attachments/assets/25497ed5-4e0d-4a1f-a13b-841675a2c969" />

**Finding:**
40 unique IP, user and reply code combinations. Key findings:

| Source IP | User | Reply Code | Count | Assessment |
|---|---|---|---|---|
| 192.168.202.102 | ftp | 227 | 2,702 | Passive mode accepted. Dominant source of activity. |
| 192.168.202.102 | ftp | 550 | 2,702 | File unavailable. Exactly matches 227 count. Upload attempt followed by failure or deletion. |
| 192.168.202.94 | anonymous | 227 | 102 | Passive mode accepted for anonymous user. |
| 192.168.202.94 | anonymous | 226 | 86 | Transfer complete. Anonymous file transfers succeeded. |
| 192.168.202.102 | anonymous | 530 | 21 | Login failed. Same IP trying multiple credential types. |
| 192.168.202.118 | unknown | 530 | 4 | Failed logins. Possible brute force. |

`192.168.202.102` is the most active IP with 2,702 passive mode requests each paired with a 550 file unavailable error. This IP is the source of the mass upload and delete activity observed in Task 3.

---

### Task 6: Investigate Suspicious File Transfers

**Query used:**
```spl
index=ftp_logs sourcetype=ftp_logs1 | rex field=_raw "^\S+\s+\S+\s+(?P<src_ip>\S+)\s+\S+\s+\S+\s+\S+\s+(?P<user>\S+)\s+\S+\s+(?P<command>\S+)\s+(?P<arg>\S+)\s+(?P<mime_type>\S+)\s+(?P<file_size>\S+)" | search command=RETR OR command=STOR | table src_ip user command arg mime_type file_size
```

**Screenshot:**
> <img width="1895" height="903" alt="image" src="https://github.com/user-attachments/assets/eda455cd-3639-48d2-8a99-4d04c233a3cc" />

**Finding:**
1,465 file transfer events revealed three distinct attack patterns:

**Attack 1: svchost.exe Malware Distribution**
Three internal IPs downloaded `svchost.exe` from `192.168.202.92` using username `ftp` and password `password`:
- `192.168.27.100` downloaded twice
- `192.168.24.100` downloaded once
- `192.168.25.100` downloaded once

All downloads: mime type `application/x-dosexec` (Windows executable), file size exactly 6,656 bytes. `svchost.exe` is a legitimate Windows process name commonly abused by malware to disguise itself. The same executable distributed to multiple machines via FTP using default credentials is consistent with lateral movement or malware deployment.

**Attack 2: Web Application Exfiltration**
`192.168.202.138` used anonymous FTP to download sensitive files from `192.168.25.101` including:
- `qdept.db` and `schema.sql` (database files)
- `registration.py`, `user_management.py`, `user.py` (Python source code)
- `nginx.conf`, `qdept.conf`, `guiconf.py` (server configuration files)

This is data exfiltration. The attacker pulled an entire web application including its database, source code and server configuration using anonymous access.

**Attack 3: Web Application Backdoor Planting**
`192.168.202.102` uploaded hundreds of Python web framework files to `192.168.23.101` under `/dept/env/lib/python2.7/site-packages/`. Every uploaded file has a `.ftpdxCfA4y` extension appended. This non-standard extension on legitimate framework files (Flask, Django, Jinja2, WTForms) suggests automated tooling planting a backdoor or modifying a web application on the target server.

---

## Summary of Findings

| Task | Key Finding |
|---|---|
| Log Upload | 5,796 events ingested. Zeek FTP log from MACCDC 2012. Timestamp fix required (Unix epoch + MAX_DAYS_AGO 6000). |
| FTP Event Search | 5,796 total events confirmed. Zeek format with binary hex data visible in some command arguments from first event. |
| File Transfer Activity | STOR at 1,353 and DELE at 1,351 almost perfectly matching. Mass upload and delete pattern indicates malware staging or cover track behaviour. |
| Anomaly Detection | 14 credential combinations. Dominant activity uses default ftp credentials. ftp/password combination linked to svchost.exe distribution. |
| User Behavior | 192.168.202.102 generated 2,702 passive mode requests each paired with 550 file unavailable errors. Most active and suspicious IP in dataset. |
| Suspicious File Transfers | Three attack patterns confirmed: svchost.exe malware distributed to 3 internal machines, web application database and source code exfiltrated anonymously, Python web framework files uploaded with suspicious extensions suggesting backdoor planting. |

---

## Key Takeaways

FTP is one of the most dangerous protocols to expose on a network because credentials and file contents are transmitted in plaintext and anonymous access is trivially exploited. This dataset contained three distinct attack patterns all made possible by weak or absent authentication on FTP servers. In a real SOC environment, FTP activity should be treated as high risk by default and any executable file transfer over FTP should trigger an immediate alert regardless of the username involved.

The STOR and DELE count match was the most subtle finding in this project. Without counting commands and comparing the numbers, this pattern would be easy to miss in a busy SOC. Building detection rules that alert on high volume upload followed by deletion within a short timeframe would catch this behaviour automatically.

Anonymous FTP access should never be permitted on a production server. Every anonymous login in this dataset was either exfiltration, reconnaissance or malware related. Zero legitimate business use was observed from anonymous credentials.

---

*Part of the SOC Skills Roadmap | Project 1: Splunk*
