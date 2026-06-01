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
- Format: Text
- Fields present: source IP, destination IP, domain name, query type, response code

### Splunk Configuration
- Index used: `dns_logs`
- Source type: `dns_logs1`

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
> [Describe what you saw. How many events were ingested? What time range do the logs cover?]

---

### Task 2: Search for DNS Events

**Query used:**
```spl
index=* sourcetype=dns_logs1
```

**Screenshot:**
> [Insert screenshot of search results]

**Finding:**
> [What did you observe? How many events returned? Any immediately visible patterns?]

---

### Task 3: Extract Relevant Fields

**Query used:**
```spl
index=* sourcetype=dns_sample | regex _raw="(?i)\b(dns|domain|query|response|port 53)\b"
```

**Screenshot:**
> [Insert screenshot showing extracted fields]

**Finding:**
> [What fields were visible? Were all expected fields present: src_ip, fqdn, query type, response code?]

---

### Task 4: Identify Anomalies (DNS Spikes)

**Query used:**
```spl
index=_* OR index=* sourcetype=dns_sample | stats count by fqdn
```

**Screenshot:**
> [Insert screenshot of stats output]

**Finding:**
> [Which domains had unusually high query counts? Did any stand out as suspicious?]

---

### Task 5: Find Top DNS Sources

**Query used:**
```spl
index=* sourcetype=dns_sample | top fqdn, src_ip
```

**Screenshot:**
> [Insert screenshot of top command output]

**Finding:**
> [Which source IPs generated the most DNS queries? Which FQDNs were queried most frequently?]

---

### Task 6: Investigate Suspicious Domains

**Query used:**
```spl
index=* sourcetype=dns_sample fqdn="[suspicious domain found in Task 4 or 5]"
```

**Screenshot:**
> [Insert screenshot]

**Finding:**
> [What did you find when you drilled into the suspicious domain? Any IOCs worth noting?]

---

## Summary of Findings

| Task | Key Finding |
|---|---|
| Log Upload | [summary] |
| DNS Event Search | [summary] |
| Field Extraction | [summary] |
| Anomaly Detection | [summary] |
| Top DNS Sources | [summary] |
| Suspicious Domain Investigation | [summary] |

---

## Key Takeaways
> [Write 2 to 3 sentences after completing the project. What did you learn? What would you do differently in a real SOC environment?]

---

*Part of the SOC Skills Roadmap | Project 1: Splunk*
