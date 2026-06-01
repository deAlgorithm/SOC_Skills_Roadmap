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
index=dns_logs sourcetype=dns_logs1 | regex _raw="(?i)\b(dns|domain|query|response|port 53)\b"
```

**Screenshot:**
> <img width="1902" height="905" alt="image" src="https://github.com/user-attachments/assets/aea16eeb-6ddc-43e0-9121-ac3f7e6c9a7d" />


**Finding:**
> [What fields were visible? Were all expected fields present: src_ip, fqdn, query type, response code?]

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
> [Which domains had unusually high query counts? Did any stand out as suspicious?]

---

### Task 5: Find Top DNS Sources

**Query used:**
```spl
index=dns_logs sourcetype=dns_logs1 | rex field=_raw "^\S+\s+\S+\s+(?P<src_ip>\S+)" | top src_ip
```

**Screenshot:**
> <img width="1917" height="904" alt="image" src="https://github.com/user-attachments/assets/1074561b-a141-4e17-8fda-3bfcc19b8a1c" />


**Finding:**
> [Which source IPs generated the most DNS queries? Which FQDNs were queried most frequently?]

---

### Task 6: Investigate Suspicious Domains

**Query used:**
```spl
index=* sourcetype=dns_sample fqdn="[suspicious domain found in Task 4 or 5]"
```

**Screenshot:**
> <img width="1896" height="889" alt="image" src="https://github.com/user-attachments/assets/3f16a7a1-cbf4-43c6-8cf7-ea30490cae7e" />
><img width="1894" height="900" alt="image" src="https://github.com/user-attachments/assets/193c14dc-07b3-4119-bac6-7a2a05fd1873" />



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
