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
- Fields present: timestamp, uid, src_ip, src_port, dest_ip, dest_port, trans_depth, method, host, uri, referrer, user_agent, request_body_length, response_body_length, status_code, status_msg

### Splunk Configuration
- Index used: `http_logs`
- Source type: `https_sample`

### Setup Notes
- Original http.log file was 1.3GB, exceeding the 500MB free version upload limit
- File was split using PowerShell to the first 100,000 lines and saved as http_sample.log (29MB)
- Timestamp format set to `%s` (Unix epoch) under Advanced timestamp settings
- `MAX_DAYS_AGO` set to `6000` to allow indexing of 2012 events
- Fields not auto-extracted. All structured queries use rex for field extraction
- The user_agent field contains multiple space-separated tokens (e.g. "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0)"), which breaks fixed-position whitespace counting for fields after it. The status code was instead extracted by matching a 3-digit number followed by a known HTTP status message

---

## Tasks and Findings

### Task 1: Upload and Verify HTTP Logs

**Steps taken:**
1. Navigated to Settings > Add Data > Upload
2. Split the original 1.3GB http.log into a 100,000-line sample using PowerShell due to the 500MB upload limit
3. Selected http_sample.log file
4. Set timestamp format to `%s` and MAX_DAYS_AGO to `6000`
5. Saved source type as `https_sample`
6. Selected `http_logs` as the index
7. Ran verification query after upload

**Query used:**
```spl
index=http_logs sourcetype=https_sample
```

**Screenshot:**
> <img width="1920" height="849" alt="image" src="https://github.com/user-attachments/assets/79ea7679-a34c-42b5-88f5-58d0f7d19309" />

**Finding:**
100,000 events successfully ingested from the sample file. Timestamps correctly reflect March 2012 dates (3/16/12) after applying the Unix epoch timestamp fix. Log covers HTTP traffic from the MACCDC 2012 competition environment. Fields are not automatically extracted by Splunk due to the Zeek log format, requiring rex-based extraction for all structured analysis.

---

### Task 2: Search for HTTP Events

**Query used:**
```spl
index=http_logs sourcetype=https_sample
```

**Screenshot:**
> <img width="1920" height="849" alt="image" src="https://github.com/user-attachments/assets/5179a03d-e57d-4aec-87b2-c697c4120204" />

**Finding:**
100,000 events returned. Raw events confirmed the Zeek HTTP log structure with tab-separated fields including timestamp, uid, source IP, source port, destination IP, destination port, transaction depth, HTTP method, host, URI, referrer, user agent, request body length, response body length, status code, and status message. First event reviewed showed a GET request from 192.168.202.110 to 192.168.22.102 for the URI /5/ using an Internet Explorer 8 user agent on Windows XP, returning a 400 Bad Request.

---

### Task 3: Analyze Web Traffic Patterns

**Query used:**
```spl
index=http_logs sourcetype=https_sample | rex field=_raw "^\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(?P<method>\S+)" | stats count by method | sort -count
```

**Screenshot:**
> <img width="1920" height="847" alt="image" src="https://github.com/user-attachments/assets/70d26d75-8bd7-499f-a985-642ede973cc5" />

**Finding:**
33 unique HTTP methods identified across 100,000 events:

| Method | Count | Assessment |
|---|---|---|
| GET | 91,763 | Normal. Standard web browsing requests. |
| HEAD | 4,732 | Notable. Header-only requests, common in scanners. |
| POST | 2,322 | Normal. Form submissions and data uploads. |
| OPTIONS | 879 | Notable. Common in CORS preflight but also reconnaissance. |
| CONNECT | 51 | Suspicious. Tunnel establishment, possible proxy abuse. |
| RPC_CONNECT | 34 | Suspicious. RPC over HTTP, unusual on a web server. |
| GNUTELLA | 28 | Notable. P2P file sharing protocol traffic detected. |
| PROPFIND | 28 | Suspicious. WebDAV method, often used by vulnerability scanners. |
| SEARCH | 25 | Suspicious. WebDAV search, scanner indicator. |
| TRACE | 12 | Suspicious. Can be used in cross-site tracing attacks. |
| NESSUS | 7 | Critical. Confirms a Nessus vulnerability scan occurred against this network. |
| PUT | 7 | Suspicious. Direct file upload capability, possible webshell vector. |
| TRACK | 7 | Suspicious. Similar risk profile to TRACE. |

The presence of `NESSUS` as an HTTP method is the single most significant finding in this task. It confirms active vulnerability scanning occurred during the capture period. Combined with `PROPFIND`, `SEARCH`, `TRACE` and `GNUTELLA`, this dataset captured a mix of automated scanning tools and non-standard protocol traffic consistent with the MACCDC red team environment.

---

### Task 4: Identify Top URIs

**Query used:**
```spl
index=http_logs sourcetype=https_sample | rex field=_raw "^\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(?P<uri>\S+)" | top limit=10 uri
```

**Screenshot:**
> <img width="1896" height="718" alt="image" src="https://github.com/user-attachments/assets/ba9803c7-4f23-489d-bd9a-889cd71c6f4d" />

**Finding:**
Top 10 URIs identified out of 100,000 events:

| URI | Count | Assessment |
|---|---|---|
| / | 8,361 | Normal. Root page requests. |
| /traq/index.php?newhook | 459 | Critical. Traq ticket system admin hook manipulation. |
| /traq/admincp/plugins.php?newhook | 459 | Critical. Traq admin panel plugin exploitation attempt. |
| /traq/admincp/plugins.php?hooks&plugin=1 | 459 | Critical. Same exploit chain, identical count to above two. |
| /phpScheduleIt/reserve.php?is_blackout=0 | 413 | Critical. Known SQL injection target in phpScheduleIt. |
| /index.php | 349 | Normal. |
| /forgotpassword.php | 299 | Notable. Password reset functionality, high volume worth monitoring. |
| /scripts/index.php | 226 | Normal application path. |
| /cgi-bin/index.php | 222 | Normal application path. |
| /\<IMG | 176 | Critical. Cross-Site Scripting (XSS) payload in URI. |

Three Traq-related URIs share an identical count of 459, indicating an automated exploit chain repeatedly targeting the Traq admin control panel plugin hook mechanism, a known vector for remote code execution. The phpScheduleIt reserve.php endpoint is a documented SQL injection target. The `/<IMG` URI is a direct XSS injection attempt. This dataset captures active exploitation attempts against multiple known vulnerable applications.

---

### Task 5: Detect Anomalies via Response Codes

**Query used:**
```spl
index=http_logs sourcetype=https_sample | rex field=_raw "\s(?P<status>\d{3})\s+(OK|Bad Request|Not Found|Forbidden|Unauthorized|Moved Permanently|Found|Service Unavailable|Internal Server Error|No Content|Created|Accepted)" | stats count by status | sort -count
```

**Screenshot:**
> <img width="1907" height="658" alt="image" src="https://github.com/user-attachments/assets/708493d8-748b-478f-bff5-85ba54e9e539" />

**Finding:**
9 unique status codes identified across 100,000 events:

| Status | Count | Percent | Assessment |
|---|---|---|---|
| 404 | 67,260 | 67.3% | Critical. Extremely high rate, strong indicator of directory scanning. |
| 200 | 13,009 | 13.0% | Normal. Legitimate successful requests. |
| 400 | 4,377 | 4.4% | Notable. Malformed requests consistent with fuzzing tools. |
| 403 | 1,588 | 1.6% | Notable. Forbidden access attempts. |
| 503 | 1,408 | 1.4% | Notable. Service unavailable, possible server strain from scanning. |
| 302 | 557 | 0.6% | Normal redirects. |
| 301 | 215 | 0.2% | Normal redirects. |
| 401 | 181 | 0.2% | Notable. Unauthorized login attempts. |
| 500 | 158 | 0.2% | Critical. Internal server errors, possible successful exploitation triggers. |

A 67.3% 404 rate is the dominant pattern in this dataset and is far outside normal traffic behaviour. This level of 404 responses indicates large-scale automated directory and file brute forcing. The 500 errors are notable given the Traq and phpScheduleIt exploitation attempts identified in Task 4, suggesting some requests may have triggered application-level failures consistent with attempted exploitation.

---

### Task 6: Investigate Suspicious IPs

**Query used:**
```spl
index=http_logs sourcetype=https_sample | rex field=_raw "^\S+\s+\S+\s+(?P<src_ip>\S+)" | top src_ip
```

**Screenshot:**
> <img width="1895" height="671" alt="image" src="https://github.com/user-attachments/assets/9b3d89b8-573b-4806-b98b-3ad5033e54d3" />

**Finding:**
Top 10 source IPs identified:

| Source IP | Count | Percent | Assessment |
|---|---|---|---|
| 192.168.202.110 | 74,695 | 74.7% | Critical. Dominant source of all HTTP traffic, strongly correlated with the 67.3% 404 rate. Likely source of directory scanning activity. |
| 192.168.202.102 | 9,236 | 9.2% | Critical. Same IP identified as the dominant source of mass STOR/DELE activity in the FTP project. |
| 192.168.202.79 | 6,070 | 6.1% | Notable. |
| 192.168.202.96 | 4,971 | 5.0% | Notable. |
| 192.168.204.45 | 1,050 | 1.1% | Normal range. |

`192.168.202.110` accounts for nearly three quarters of all HTTP traffic in the dataset. Given the overall 67.3% 404 rate, this IP is the most likely source of the directory scanning activity observed in Task 5. `192.168.202.102` appearing as the second most active IP here, after also being the dominant source of suspicious upload and delete activity in the FTP project, suggests this host is either compromised or is the attacker's primary pivot point on this network. This is a significant cross-project correlation.

---

## Summary of Findings

| Task | Key Finding |
|---|---|
| Log Upload | 100,000 events ingested from a 100,000-line sample of the original 1.3GB log due to free version upload limits. Timestamp fix required (Unix epoch + MAX_DAYS_AGO 6000). |
| HTTP Event Search | 100,000 total events confirmed. Zeek format with 16-field structure including multi-token user agent strings. |
| Web Traffic Patterns | NESSUS confirmed as an HTTP method, indicating active vulnerability scanning. PROPFIND, SEARCH, TRACE and GNUTELLA also present. |
| Top URIs | Traq admin panel plugin hook exploitation (459 hits across 3 URIs), phpScheduleIt SQL injection target (413 hits), and XSS payload in URI (/\<IMG, 176 hits) identified. |
| Anomaly Detection | 67.3% of all responses were 404, indicating large-scale directory and file scanning. 500 errors present, possibly from exploitation attempts. |
| Suspicious IP Investigation | 192.168.202.110 generated 74.7% of all HTTP traffic, the likely source of the scanning activity. 192.168.202.102 reappears from the FTP project as a second major suspicious actor. |

---

## Key Takeaways

HTTP log analysis revealed clear evidence of automated scanning and exploitation attempts, including a confirmed Nessus scan, WebDAV scanning methods, an XSS payload, and exploitation attempts against two known vulnerable applications (Traq and phpScheduleIt). The 67.3% 404 rate driven by a single IP was the clearest single indicator of scanning behaviour and would be one of the first things to alert on in a real SOC environment.

The most valuable insight from this project was discovering that `192.168.202.102`, the IP responsible for mass upload and delete activity in the FTP project, also appears as a major source of HTTP traffic here. Correlating activity across multiple log sources for the same IP is exactly the kind of cross-log analysis a SOC analyst performs during an investigation, and this project demonstrated why having multiple log types available matters.

Field extraction continues to be the main technical challenge with Zeek logs. The variable-length user agent field broke fixed-position regex extraction for every field after it, requiring a different extraction strategy based on pattern matching against known status messages rather than positional counting. This is a reusable lesson for any future Zeek-based log analysis.

---

*Part of the SOC Skills Roadmap | Project 1: Splunk*
