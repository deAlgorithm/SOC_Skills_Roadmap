# HTTP Log Analysis Using Splunk
 
## Objective
Analyze HTTP log files using Splunk to monitor web traffic patterns, detect anomalies, identify suspicious requests, and uncover potential security threats within network activity.
 
## Tools Used
- Splunk Enterprise 10.2.0 (local instance)
- Sample HTTP log file (secrepo.com - MACCDC 2012 dataset)
## MITRE ATT&CK Mapping
| Technique | ID | Tactic |
|---|---|---|
| Exploit Public-Facing Application | T1190 | Initial Access |
| Web Shell | T1505.003 | Persistence |
| Data Exfiltration Over Web Service | T1567 | Exfiltration |
 
---
 
## Setup
 
### Log File
- Source: secrepo.com sample HTTP log (http.log.gz)
- Format: Zeek/Bro tab-separated log
- Fields present: timestamp, uid, src_ip, src_port, dest_ip, dest_port, method, host, uri, referrer, user_agent, status_code, response_body_length
### Splunk Configuration
- Index used: `http_logs`
- Source type: `http_logs1`
### Setup Notes
- Same MACCDC 2012 dataset as DNS and FTP projects
- Timestamp format set to `%s` (Unix epoch) under Advanced timestamp settings
- `MAX_DAYS_AGO` set to `6000` to allow indexing of 2012 events
- Fields not auto-extracted. All structured queries use rex for field extraction
---
 
## Tasks and Findings
 
### Task 1: Upload and Verify HTTP Logs
 
**Steps taken:**
1. Navigated to Settings > Add Data > Upload
2. Selected http.log file
3. Set timestamp format to `%s` and MAX_DAYS_AGO to `6000`
4. Saved source type as `http_logs1`
5. Selected `http_logs` as the index
6. Ran verification query after upload
**Query used:**
```spl
index=http_logs sourcetype=http_logs1
```
 
**Screenshot:**
> <img width="1920" height="849" alt="image" src="https://github.com/user-attachments/assets/79ea7679-a34c-42b5-88f5-58d0f7d19309" />

 
**Finding:**
> [How many events were ingested? What time range do the logs cover?]
 
---
 
### Task 2: Search for HTTP Events
 
**Query used:**
```spl
index=http_logs sourcetype=http_logs1
```
 
**Screenshot:**
> mc
<img width="1920" height="849" alt="image" src="https://github.com/user-attachments/assets/5179a03d-e57d-4aec-87b2-c697c4120204" />
 
**Finding:**
> [How many events returned? What fields are visible in the raw events?]
 
---
 
### Task 3: Analyze Web Traffic Patterns
 
**Query used:**
```spl
index=http_logs sourcetype=http_logs1 | rex field=_raw "^\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(?P<method>\S+)\s+\S+\s+(?P<uri>\S+)\s+\S+\s+\S+\s+(?P<status>\S+)" | stats count by method | sort -count
```
 
**Screenshot:**
> [Insert screenshot of method distribution]
 
**Finding:**
> [What HTTP methods were used? GET vs POST ratio? Any unusual methods like PUT, DELETE, HEAD?]
 
---
 
### Task 4: Identify Top URIs
 
**Query used:**
```spl
index=http_logs sourcetype=http_logs1 | rex field=_raw "^\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(?P<uri>\S+)" | top limit=10 uri
```
 
**Screenshot:**
> [Insert screenshot of top URIs]
 
**Finding:**
> [Which URIs were accessed most frequently? Any suspicious paths like admin panels, shell uploads, or scanning patterns?]
 
---
 
### Task 5: Detect Anomalies via Response Codes
 
**Query used:**
```spl
index=http_logs sourcetype=http_logs1 | rex field=_raw "^\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(?P<status>\S+)" | stats count by status | sort -count
```
 
**Screenshot:**
> [Insert screenshot of response code distribution]
 
**Finding:**
> [What response codes appeared? High 404 counts indicate scanning. High 500 counts indicate exploitation attempts. Any 200 responses to suspicious URIs?]
 
---
 
### Task 6: Investigate Suspicious IPs
 
**Query used:**
```spl
index=http_logs sourcetype=http_logs1 | rex field=_raw "^\S+\s+\S+\s+(?P<src_ip>\S+)\s+\S+\s+\S+\s+\S+\s+(?P<method>\S+)\s+\S+\s+(?P<uri>\S+)\s+\S+\s+\S+\s+(?P<status>\S+)" | stats count by src_ip | sort -count
```
 
**Screenshot:**
> [Insert screenshot of top source IPs]
 
**Finding:**
> [Which IPs generated the most HTTP requests? Any IPs with high error rates or scanning patterns?]
 
---
 
## Summary of Findings
 
| Task | Key Finding |
|---|---|
| Log Upload | [summary] |
| HTTP Event Search | [summary] |
| Web Traffic Patterns | [summary] |
| Top URIs | [summary] |
| Anomaly Detection | [summary] |
| Suspicious IP Investigation | [summary] |
 
---
 
## Key Takeaways
> [Write 2 to 3 sentences after completing the project. What did you learn? What would you do differently in a real SOC environment?]
 
---
 
*Part of the SOC Skills Roadmap | Project 1: Splunk*
