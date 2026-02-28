# Phishing-Email-Analyzer
A Python-based phishing email detection tool built as a **SOC L1 Portfolio Project** — analyzes `.eml` files for threats using header inspection, keyword detection, URL analysis, and spoofing indicators, with results exported as CSV and a dark-themed HTML dashboard.

---

## 🚀 Features

- 📋 **Email Header Analysis** — Extracts From, To, Subject, Sender IP, Reply-To, and X-Mailer fields
- 🔑 **Phishing Keyword Detection** — Scans for 30+ common phishing trigger words (urgent, OTP, ATM PIN, etc.)
- 🔗 **Suspicious URL Detection** — Flags malicious TLDs (`.xyz`, `.tk`), suspicious keywords in URLs, and HTTP links
- 🕵️ **Spoofing Detection** — Detects Reply-To mismatches, typosquatted domains, brand impersonation, and bulk mailer tools
- 📎 **Dangerous Attachment Detection** — Flags `.exe`, `.zip`, `.bat`, `.vbs`, `.jar`, and more
- 🎯 **Risk Scoring** — Each email gets a score from 0–100 with a verdict: 🟢 Safe / 🟡 Suspicious / 🔴 High Risk
- 📊 **CSV Report** — Structured data export for further analysis
- 🌐 **HTML Dashboard** — Dark-themed interactive report with summary stats and detailed cards per email

---

## 📁 Project Structure

```
phishing-email-analyzer/
│
├── phishing_analyzer.py       ← Main analyzer script
│
├── emails/                    ← Place .eml files here
│   ├── legitimate_github.eml
│   ├── phishing_bank.eml
│   └── phishing_job.eml
│
└── reports/                   ← Auto-generated output
    ├── phishing_report.csv
    └── phishing_report.html
```

---

## 🛠️ Tech Stack

| Tool | Purpose |
|------|---------|
| Python 3.x | Core language |
| `re` | Regex-based header & URL parsing |
| `csv` | Structured report export |
| `datetime` | Timestamp generation |
| HTML + CSS | Dark-themed dashboard (no external libraries) |

---

## ⚙️ How to Run

**1. Clone the repository**
```bash
git clone https://github.com/YOUR_USERNAME/phishing-email-analyzer.git
cd phishing-email-analyzer
```

**2. Add your `.eml` files to the `emails/` folder**

**3. Run the analyzer**
```bash
python phishing_analyzer.py
```

**4. View your reports in the `reports/` folder**
- Open `phishing_report.html` in any browser for the dashboard
- Open `phishing_report.csv` in Excel or Google Sheets

> ✅ No external libraries required — runs on standard Python 3!

---

## 📊 Sample Output

```
📧 Starting Phishing Email Analyzer...
   Timestamp: 2026-02-28 22:54:32
   Scanning folder: emails/
   Found 3 email(s) to analyze

🔍 Analyzing: phishing_bank.eml
=================================================================
  🎯 RISK SCORE : 100/100
  📊 VERDICT   : 🔴 HIGH RISK — PHISHING
=================================================================
⚠️  REASONS:
   • High phishing keyword count (8 keywords found)
   • Suspicious URL detected
   • Multiple spoofing indicators (2)
   • Dangerous attachment type found: .exe
```

---

## 🧪 Test Emails Included

| File | Verdict | Risk Score |
|------|---------|-----------|
| `legitimate_github.eml` | 🟢 SAFE | 0/100 |
| `phishing_bank.eml` | 🔴 HIGH RISK | 100/100 |
| `phishing_job.eml` | 🔴 HIGH RISK | 100/100 |

---

## 🔍 Detection Logic

### Risk Score Breakdown
| Indicator | Points |
|-----------|--------|
| 5+ phishing keywords | +40 |
| 1–4 phishing keywords | +20 |
| Suspicious URL found | +30 |
| 2+ spoofing indicators | +20 |
| 1 spoofing indicator | +10 |
| Dangerous attachment | +10 |

### Spoofing Checks
- Reply-To domain differs from sender domain
- Brand impersonation (HDFC, TCS, Google, etc.) with mismatched domain
- Typosquatted domain patterns (`-verify`, `-login`, `-secure`, `.xyz`)
- Sent via bulk mailing tools (PHPMailer, Bulk Mailer Pro)

---

## 🎯 Use Cases

- SOC L1 analyst email triage simulation
- Cybersecurity awareness training
- Learning email header forensics
- Portfolio demonstration for security roles

---

## 👩‍💻 Author

**Swathi V**  
Cybersecurity Enthusiast | SOC L1 Aspirant  

---

## 📄 License

This project is open source and available under the [MIT License](LICENSE).

---

> ⚠️ **Disclaimer:** The phishing email samples included are **simulated/fictional** and created purely for educational purposes. Do not use this tool on real emails without proper authorization.
