# Real-Time Network Monitoring with Automated PowerShell Mitigation for Low-Bandwidth Environments

A lightweight, local Security Operations Center (SOC) web application built to automate raw email forensic analysis, extract network and authentication telemetry, query live threat intelligence APIs, and streamline initial incident triage for Tier 1 analysts.

---

## Key Features

- **Raw Email Parsing (`.eml`):** Automatically ingests raw email files, decoding headers, MIME structures, sender details, subject lines, body text, and embedded links.
- **Authentication Telemetry Auditing:** Evaluates **SPF**, **DKIM**, and **DMARC** validation results to identify spoofed domains and phishing indicators.
- **Automated Threat Intelligence Ingestion:** 
  - Queries **AbuseIPDB API** to check the reputation score of originating routing IPs.
  - Queries **VirusTotal v3 API** to scan extracted URLs and file hash indicators.
- **Dynamic Risk Scoring:** Aggregates authentication failures and threat intelligence data into a calculated severity rating.
- **Flat-File Event Persistence:** Logs all triaged emails, extracted IOCs, and analyst risk scores into `triage_database.csv` for auditability and historical tracking.

---

## Technical Stack

| Component | Technology / Library |
| :--- | :--- |
| **Backend Framework** | Python 3.x, Flask |
| **Frontend UI** | Jinja2, HTML5, CSS3 |
| **Parsing Engine** | Native Python `email` & `built-in` libraries |
| **Threat Intelligence** | AbuseIPDB API, VirusTotal v3 API |
| **Data Persistence** | CSV Flat-File Storage (`triage_database.csv`) |

---

## Installation & Setup

### Prerequisites

- **Python 3.8+** installed on your operating system.
- API keys for **AbuseIPDB** and **VirusTotal v3**.

### Step 1: Clone the Repository

```bash
git clone [https://github.com/Samuvelponkanth/phishing-email-triage-pipeline.git](https://github.com/Samuvelponkanth/phishing-email-triage-pipeline.git)
cd phishing-email-triage-pipeline