# DNS Log Analysis Using Splunk

## Objective
Analyze DNS log files using Splunk to identify anomalies, suspicious domains, and potential security threats within network traffic.

## Tools Used
- Splunk (local instance)
- Sample DNS log file (secrepo.com)

## MITRE ATT&CK Mapping
| Technique | ID | Tactic |
|---|---|---|
| DNS | T1071.004 | Command and Control |
| Domain Generation Algorithms | T1568.002 | Command and Control |

---

## Setup

### Log File
- Source: secrepo.com sample DNS log (dns.log.gz)
- Format: Zeek/Bro tab-separated log
- Fields present: source IP, destination IP, domain name, query type, response code

### Splunk Configuration
- Index used: `dns_logs`
- Source type: `dns_logs1`

### Setup Notes
- Log file contains data from March 2012 (MACCDC 2012 competition dataset)
- Timestamp format required manual configuration. Set to `%s` (Unix epoch) under Advanced timestamp settings
- `MAX_DAYS_AGO` set to `6000` to allow indexing of events from 2012
- A new index `dns_logs` was created instead of using the default `main` index to keep project data organised
- Splunk did not auto-extract fields from the Zeek log format. All field extraction was done inline using `rex` commands

---

## Tasks and Findings

### Task 1: Upload and Verify DNS Logs

**Steps taken:**
1. Navigated to Settings > Add Data > Upload
2. Selected dns.log file
3. Set source type to `dns_logs1`
4. Confirmed index and host settings
5. Ran verification query after upload

**Query used:**
```spl
index="dns_logs" sourcetype="dns_logs1"
```

**Screenshot:**
> <img width="1840" height="850" alt="image" src="https://github.com/user-attachments/assets/b787b2f2-7e30-40fc-960b-55a3b85254f2" />

**Finding:**
427,935 events successfully ingested. Timestamps correctly reflect March 2012 dates after applying the Unix epoch timestamp fix. Log covers network traffic from the MACCDC 2012 competition environment. Fields are not automatically extracted by Splunk due to the Zeek log format, requiring rex-based extraction for all structured analysis.

---

### Task 2: Search for DNS Events

**Query used:**
```spl
index=* sourcetype=dns_logs1
```

**Screenshot:**
> <img width="1912" height="899" alt="image" src="https://github.com/user-attachments/assets/e6d1be12-9a6e-4790-abd8-1dfef11d9d13" />


**Finding:**
427,935 events returned. Reviewing individual events confirmed the Zeek DNS log structure with tab-separated fields including source IP, destination IP, port 53 as destination, UDP protocol, domain query, query type and response code. First event reviewed showed a Windows machine at 192.168.202.141 querying s.msftncsi.com (Microsoft network connectivity check) and receiving an NXDOMAIN response, indicating no internet access at that time.

---

### Task 3: Extract Relevant Fields

**Query used:**
```spl
index=dns_logs sourcetype=dns_logs1 | regex _raw="(?i)\b(dns|domain|query|response|port 53)\b"
```

**Screenshot:**
> <img width="1902" height="905" alt="image" src="https://github.com/user-attachments/assets/aea16eeb-6ddc-43e0-9121-ac3f7e6c9a7d" />

**Finding:**
1,432 events matched the DNS keyword filter out of 427,935 total. The raw log fields were confirmed present: source IP, destination IP, query domain, query type (A, PTR, NB) and response code (NXDOMAIN, NOERROR). Fields are not named automatically in this log format. Splunk treats the entire line as raw text. Field extraction using rex was required for structured analysis in subsequent tasks.

---

### Task 4: Identify Anomalies (DNS Spikes)

**Query used:**
```spl
index=dns_logs sourcetype=dns_logs1 | rex field=_raw "^\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(?P<query>\S+)" | stats count by query | sort -count
```

**Screenshot:**
> <img width="1900" height="885" alt="image" src="https://github.com/user-attachments/assets/4ed4dcce-c6be-433e-975b-3eb55a170af1" />
<img width="1892" height="786" alt="image" src="https://github.com/user-attachments/assets/86f15633-63f8-4b0f-add7-90b3a2778712" />

**Finding:**
5,175 unique domains identified across 427,935 events. Top domains by query count:

| Domain | Count | Assessment |
|---|---|---|
| teredo.ipv6.microsoft.com | 39,273 | Normal. Microsoft IPv6 tunneling. |
| tools.google.com | 14,057 | Normal. Google software updates. |
| www.apple.com | 13,390 | Normal. Apple device check-ins. |
| time.apple.com | 13,109 | Normal. Apple time sync. |
| safebrowsing.clients.google.com | 11,658 | Normal. Chrome safe browsing checks. |
| *\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00 | 10,401 | Suspicious. Null bytes in DNS query. Possible DNS tunneling or malformed exploit traffic. |
| WPAD | 9,134 | Suspicious. High WPAD query volume can indicate WPAD poisoning attempts. |
| 44.206.168.192.in-addr.arpa | 7,248 | Notable. High volume PTR reverse lookup. Possible network reconnaissance. |
| ISATAP | 6,569 | Notable. Microsoft IPv6 tunneling protocol. High count worth monitoring. |

The null bytes entry is the most significant anomaly. Legitimate domain names never contain null bytes. This pattern is associated with DNS tunneling or exploitation attempts.

---

### Task 5: Find Top DNS Sources

**Query used:**
```spl
index=dns_logs sourcetype=dns_logs1 | rex field=_raw "^\S+\s+\S+\s+(?P<src_ip>\S+)" | top src_ip
```

**Screenshot:**
> <img width="1917" height="904" alt="image" src="https://github.com/user-attachments/assets/1074561b-a141-4e17-8fda-3bfcc19b8a1c" />

**Finding:**
Top 10 source IPs identified. `10.10.117.210` generated 75,943 queries, accounting for 17.7% of all DNS traffic in the dataset. This is more than double the next highest source at 26,522 queries. The volume spike on a single IP warranted further investigation in Task 6.

| Source IP | Count | Percent |
|---|---|---|
| 10.10.117.210 | 75,943 | 17.75% |
| 192.168.202.93 | 26,522 | 6.20% |
| 192.168.202.103 | 18,121 | 4.23% |
| 192.168.202.76 | 16,978 | 3.97% |
| 192.168.202.97 | 16,176 | 3.78% |

---

### Task 6: Investigate Suspicious Domains

**Query used:**
```spl
index=dns_logs sourcetype=dns_logs1 | rex field=_raw "^\S+\s+\S+\s+(?P<src_ip>\S+)\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(?P<query>\S+)" | search src_ip="10.10.117.210" | stats count by query | sort -count
```

**Screenshot:**
> <img width="1896" height="889" alt="image" src="https://github.com/user-attachments/assets/3f16a7a1-cbf4-43c6-8cf7-ea30490cae7e" />
><img width="1894" height="900" alt="image" src="https://github.com/user-attachments/assets/193c14dc-07b3-4119-bac6-7a2a05fd1873" />

**Finding:**
75,943 events confirmed for this IP across 250 unique domains. Top queries included teredo.ipv6.microsoft.com (27,425), tools.google.com (10,179), stats.norton.com (3,976) and liveupdate.symantecliveupdate.com (1,763). The machine also queried `_autodiscover._tcp.soleranetworks.com` and `owa.fireeye.com`. Solera Networks produces network forensics appliances and FireEye is a security vendor. The query pattern and vendor-specific domains suggest `10.10.117.210` is a security monitoring appliance rather than a standard workstation. High DNS volume from this IP is consistent with active network monitoring behaviour, not malicious activity. No IOCs confirmed for this IP.

---

## Summary of Findings

| Task | Key Finding |
|---|---|
| Log Upload | 427,935 events ingested. Zeek DNS log from MACCDC 2012. Timestamp fix required (Unix epoch + MAX_DAYS_AGO 6000). |
| DNS Event Search | 427,935 total events. Zeek format confirmed. First event showed NXDOMAIN response for Microsoft connectivity check domain. |
| Field Extraction | 1,432 events matched DNS keyword filter. Fields not auto-extracted. rex commands required for all structured queries. |
| Anomaly Detection | Null bytes in DNS query at 10,401 occurrences is the top anomaly. WPAD at 9,134 and high PTR reverse lookup volume also notable. |
| Top DNS Sources | 10.10.117.210 generated 17.7% of all DNS traffic. Significant spike compared to all other hosts on the network. |
| Suspicious Domain Investigation | 10.10.117.210 identified as likely security monitoring appliance based on query patterns to Solera Networks and FireEye domains. High volume explained by device role. No IOCs confirmed. |

---

## Key Takeaways

DNS analysis in Splunk requires understanding the log format before running any queries. The Zeek DNS log did not auto-extract fields, which meant every structured query required manual rex extraction. In a real SOC environment this would be solved by installing the Splunk Add-on for Zeek or configuring proper field extractions at the source type level, saving significant query complexity.

The most valuable finding was the null bytes DNS query appearing 10,401 times. In a live environment this would be an immediate escalation trigger. DNS queries should never contain null bytes and their presence indicates either DNS tunneling, exploitation attempts, or malware communication.

High DNS query volume from a single IP is not automatically suspicious. Context matters. `10.10.117.210` appeared alarming on first look but investigation revealed it was likely a security appliance. Always investigate before concluding.

---

*Part of the SOC Skills Roadmap | Project 1: Splunk*
