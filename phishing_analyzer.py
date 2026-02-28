"""
=============================================================
  📧 PHISHING EMAIL ANALYZER
  Built for: SOC L1 Portfolio Project
  Description: Analyzes email files to detect phishing
               using header analysis, URL checking,
               keyword detection, and spoofing detection
=============================================================
"""

import re
import os
import csv
import datetime
from collections import defaultdict

# ─────────────────────────────────────────────
# ⚙️  CONFIGURATION
# ─────────────────────────────────────────────
EMAILS_FOLDER  = "emails"
CSV_REPORT     = "reports/phishing_report.csv"
HTML_REPORT    = "reports/phishing_report.html"

# Phishing keywords commonly found in phishing emails
PHISHING_KEYWORDS = [
    "urgent", "immediately", "suspended", "verify your account",
    "click here", "confirm your", "unusual activity", "limited time",
    "act now", "expire", "permanently closed", "security alert",
    "update your", "validate", "congratulations", "you have been selected",
    "pay", "registration fee", "offer letter", "bank account details",
    "aadhar", "pan card", "otp", "atm pin", "password", "login",
    "winner", "prize", "free", "claim", "account suspended"
]

# Suspicious attachment extensions
SUSPICIOUS_EXTENSIONS = [
    ".exe", ".zip", ".rar", ".bat", ".cmd", ".vbs",
    ".js", ".jar", ".scr", ".pif"
]

# Trusted legitimate domains
TRUSTED_DOMAINS = [
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "github.com", "google.com", "microsoft.com", "apple.com",
    "amazon.com", "linkedin.com", "twitter.com", "facebook.com",
    "hdfc.com", "sbi.co.in", "icicibank.com", "tcs.com",
    "infosys.com", "wipro.com", "naukri.com"
]


# ─────────────────────────────────────────────
# 📂 STEP 1: Read Email File
# ─────────────────────────────────────────────
def read_email(filepath):
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except FileNotFoundError:
        print(f"❌ File not found: {filepath}")
        return ""


# ─────────────────────────────────────────────
# 🔍 STEP 2: Extract Email Headers
# ─────────────────────────────────────────────
def extract_headers(content):
    headers = {}

    patterns = {
        'from':       r'From:\s*(.+)',
        'to':         r'To:\s*(.+)',
        'subject':    r'Subject:\s*(.+)',
        'date':       r'Date:\s*(.+)',
        'reply_to':   r'Reply-To:\s*(.+)',
        'received':   r'Received:\s*(.+)',
        'x_mailer':   r'X-Mailer:\s*(.+)',
        'message_id': r'Message-ID:\s*(.+)',
    }

    for key, pattern in patterns.items():
        match = re.search(pattern, content, re.IGNORECASE)
        headers[key] = match.group(1).strip() if match else "Not Found"

    # Extract sender email address
    from_match = re.search(r'[\w\.-]+@[\w\.-]+', headers.get('from', ''))
    headers['sender_email'] = from_match.group(0).lower() if from_match else "unknown"

    # Extract sender domain
    if '@' in headers.get('sender_email', ''):
        headers['sender_domain'] = headers['sender_email'].split('@')[1]
    else:
        headers['sender_domain'] = "unknown"

    # Extract reply-to email
    reply_match = re.search(r'[\w\.-]+@[\w\.-]+', headers.get('reply_to', ''))
    headers['reply_to_email'] = reply_match.group(0).lower() if reply_match else "Not Found"

    # Extract IP from Received header
    ip_match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', headers.get('received', ''))
    headers['sender_ip'] = ip_match.group(1) if ip_match else "Not Found"

    return headers


# ─────────────────────────────────────────────
# 🔗 STEP 3: Extract URLs
# ─────────────────────────────────────────────
def extract_urls(content):
    url_pattern = re.compile(
        r'https?://[^\s<>"\']+|www\.[^\s<>"\']+',
        re.IGNORECASE
    )
    urls = url_pattern.findall(content)
    return list(set(urls))  # remove duplicates


# ─────────────────────────────────────────────
# 📎 STEP 4: Check Attachments
# ─────────────────────────────────────────────
def check_attachments(content):
    suspicious = []
    attachment_pattern = re.compile(
        r'[\w\s\-]+(' + '|'.join(re.escape(ext) for ext in SUSPICIOUS_EXTENSIONS) + r')',
        re.IGNORECASE
    )
    matches = attachment_pattern.findall(content)
    for ext in matches:
        suspicious.append(ext)
    return suspicious


# ─────────────────────────────────────────────
# 🔑 STEP 5: Check Phishing Keywords
# ─────────────────────────────────────────────
def check_keywords(content):
    found = []
    content_lower = content.lower()
    for keyword in PHISHING_KEYWORDS:
        if keyword.lower() in content_lower:
            found.append(keyword)
    return found


# ─────────────────────────────────────────────
# 🕵️  STEP 6: Detect Spoofing
# ─────────────────────────────────────────────
def detect_spoofing(headers):
    flags = []

    sender_domain  = headers.get('sender_domain', '')
    reply_to_email = headers.get('reply_to_email', '')
    sender_email   = headers.get('sender_email', '')
    x_mailer       = headers.get('x_mailer', '').lower()
    from_header    = headers.get('from', '').lower()

    # Check 1: Reply-To different from sender
    if reply_to_email != "Not Found" and sender_email != "unknown":
        sender_dom  = sender_email.split('@')[-1] if '@' in sender_email else ''
        reply_dom   = reply_to_email.split('@')[-1] if '@' in reply_to_email else ''
        if sender_dom and reply_dom and sender_dom != reply_dom:
            flags.append(f"Reply-To domain ({reply_dom}) differs from sender ({sender_dom})")

    # Check 2: Sender domain not in trusted list but claims to be trusted brand
    trusted_brands = ['hdfc', 'sbi', 'icici', 'tcs', 'infosys', 'google',
                      'microsoft', 'amazon', 'apple', 'paypal', 'bank']
    for brand in trusted_brands:
        if brand in from_header and brand not in sender_domain:
            flags.append(f"Claims to be '{brand}' but domain is '{sender_domain}'")

    # Check 3: Suspicious sender domain patterns (typosquatting)
    suspicious_patterns = ['-verify', '-secure', '-login', '-alert',
                           '-update', '-confirm', 'verify-', 'secure-',
                           '-india.net', '-portal', '.xyz', '.tk', '.ml']
    for pattern in suspicious_patterns:
        if pattern in sender_domain:
            flags.append(f"Suspicious domain pattern '{pattern}' in {sender_domain}")

    # Check 4: Bulk mailer tools
    bulk_mailers = ['phpmailer', 'bulk mailer', 'mass mailer', 'sendgrid bulk']
    for mailer in bulk_mailers:
        if mailer in x_mailer:
            flags.append(f"Sent via bulk mailing tool: {headers.get('x_mailer', '')}")

    return flags


# ─────────────────────────────────────────────
# 🌐 STEP 7: Analyze URLs
# ─────────────────────────────────────────────
def analyze_urls(urls):
    suspicious_urls = []
    for url in urls:
        reasons = []
        url_lower = url.lower()

        # Check for suspicious TLDs
        suspicious_tlds = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.click']
        for tld in suspicious_tlds:
            if tld in url_lower:
                reasons.append(f"Suspicious TLD: {tld}")

        # Check for IP address in URL instead of domain
        if re.search(r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
            reasons.append("IP address used instead of domain name")

        # Check for misleading keywords in URL
        url_keywords = ['login', 'verify', 'secure', 'account', 'update',
                        'confirm', 'suspend', 'payment', 'offer', 'free']
        for kw in url_keywords:
            if kw in url_lower:
                reasons.append(f"Suspicious keyword in URL: '{kw}'")
                break

        # Check if URL domain matches trusted brands
        trusted_brands = ['hdfc', 'sbi', 'tcs', 'google', 'microsoft', 'paypal']
        for brand in trusted_brands:
            if brand in url_lower:
                domain_match = re.search(r'https?://([^/]+)', url)
                if domain_match:
                    domain = domain_match.group(1)
                    if brand not in domain.split('.')[-2]:
                        reasons.append(f"Brand '{brand}' in URL but domain is suspicious: {domain}")

        if reasons:
            suspicious_urls.append({'url': url, 'reasons': reasons})

    return suspicious_urls


# ─────────────────────────────────────────────
# 🎯 STEP 8: Calculate Risk Score
# ─────────────────────────────────────────────
def calculate_risk(keywords, suspicious_urls, spoofing_flags, attachments):
    score = 0
    reasons = []

    # Keywords found
    if len(keywords) >= 5:
        score += 30
        reasons.append(f"High phishing keyword count ({len(keywords)} keywords found)")
    elif len(keywords) >= 3:
        score += 20
        reasons.append(f"Multiple phishing keywords found ({len(keywords)})")
    elif len(keywords) >= 1:
        score += 10
        reasons.append(f"Some phishing keywords found ({len(keywords)})")

    # Suspicious URLs
    if len(suspicious_urls) >= 2:
        score += 30
        reasons.append(f"Multiple suspicious URLs detected ({len(suspicious_urls)})")
    elif len(suspicious_urls) == 1:
        score += 20
        reasons.append("Suspicious URL detected")

    # Spoofing flags
    if len(spoofing_flags) >= 2:
        score += 30
        reasons.append(f"Multiple spoofing indicators ({len(spoofing_flags)})")
    elif len(spoofing_flags) == 1:
        score += 20
        reasons.append("Spoofing indicator detected")

    # Dangerous attachments
    if attachments:
        score += 20
        reasons.append(f"Dangerous attachment type found: {', '.join(attachments)}")

    # Determine verdict
    if score >= 70:
        verdict = "🔴 HIGH RISK — PHISHING"
        verdict_short = "HIGH RISK"
    elif score >= 40:
        verdict = "🟡 MEDIUM RISK — SUSPICIOUS"
        verdict_short = "SUSPICIOUS"
    elif score >= 10:
        verdict = "🟠 LOW RISK — REVIEW NEEDED"
        verdict_short = "LOW RISK"
    else:
        verdict = "🟢 LIKELY SAFE"
        verdict_short = "SAFE"

    return score, verdict, verdict_short, reasons


# ─────────────────────────────────────────────
# 🖨️  STEP 9: Print Terminal Report
# ─────────────────────────────────────────────
def print_report(filename, headers, keywords, suspicious_urls,
                 spoofing_flags, attachments, score, verdict, reasons):
    print("\n" + "="*65)
    print(f"  📧 PHISHING ANALYSIS REPORT")
    print(f"  File: {filename}")
    print("="*65)

    print(f"\n📋 EMAIL HEADERS")
    print(f"   From       : {headers.get('from', 'N/A')}")
    print(f"   To         : {headers.get('to', 'N/A')}")
    print(f"   Subject    : {headers.get('subject', 'N/A')}")
    print(f"   Sender IP  : {headers.get('sender_ip', 'N/A')}")
    print(f"   Reply-To   : {headers.get('reply_to', 'N/A')}")
    print(f"   X-Mailer   : {headers.get('x_mailer', 'N/A')}")

    print(f"\n🔑 PHISHING KEYWORDS FOUND ({len(keywords)})")
    if keywords:
        print(f"   {', '.join(keywords[:10])}")
    else:
        print("   None found")

    print(f"\n🔗 SUSPICIOUS URLs ({len(suspicious_urls)})")
    if suspicious_urls:
        for item in suspicious_urls:
            print(f"   ⚠️  {item['url'][:60]}")
            for r in item['reasons']:
                print(f"       → {r}")
    else:
        print("   None found")

    print(f"\n🕵️  SPOOFING INDICATORS ({len(spoofing_flags)})")
    if spoofing_flags:
        for flag in spoofing_flags:
            print(f"   ⚠️  {flag}")
    else:
        print("   None found")

    print(f"\n📎 SUSPICIOUS ATTACHMENTS ({len(attachments)})")
    if attachments:
        print(f"   ⚠️  {', '.join(attachments)}")
    else:
        print("   None found")

    print(f"\n{'='*65}")
    print(f"  🎯 RISK SCORE : {score}/100")
    print(f"  📊 VERDICT   : {verdict}")
    print(f"{'='*65}")

    if reasons:
        print(f"\n⚠️  REASONS:")
        for r in reasons:
            print(f"   • {r}")
    print()


# ─────────────────────────────────────────────
# 💾 STEP 10: Save CSV Report
# ─────────────────────────────────────────────
def save_csv(results):
    os.makedirs("reports", exist_ok=True)
    with open(CSV_REPORT, "w", newline="", encoding="utf-8") as f:
        fieldnames = ['File', 'From', 'Subject', 'Sender IP', 'Risk Score',
                      'Verdict', 'Keywords Found', 'Suspicious URLs',
                      'Spoofing Flags', 'Suspicious Attachments']
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow({
                'File': r['file'],
                'From': r['headers'].get('from', ''),
                'Subject': r['headers'].get('subject', ''),
                'Sender IP': r['headers'].get('sender_ip', ''),
                'Risk Score': r['score'],
                'Verdict': r['verdict_short'],
                'Keywords Found': len(r['keywords']),
                'Suspicious URLs': len(r['suspicious_urls']),
                'Spoofing Flags': len(r['spoofing_flags']),
                'Suspicious Attachments': ', '.join(r['attachments']) if r['attachments'] else 'None'
            })
    print(f"💾 CSV report saved → {CSV_REPORT}")


# ─────────────────────────────────────────────
# 🌐 STEP 11: Save HTML Report
# ─────────────────────────────────────────────
def save_html(results):
    os.makedirs("reports", exist_ok=True)

    def badge(verdict_short):
        colors = {
            "HIGH RISK": "#ff4444",
            "SUSPICIOUS": "#ff9900",
            "LOW RISK": "#ffcc00",
            "SAFE": "#00cc44"
        }
        return colors.get(verdict_short, "#999")

    rows = ""
    cards = ""
    for r in results:
        color = badge(r['verdict_short'])
        rows += f"""
        <tr>
            <td>{r['file']}</td>
            <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis">{r['headers'].get('from','')}</td>
            <td style="max-width:200px;overflow:hidden;text-overflow:ellipsis">{r['headers'].get('subject','')}</td>
            <td>{r['headers'].get('sender_ip','')}</td>
            <td><b>{r['score']}/100</b></td>
            <td><span style="background:{color};color:white;padding:3px 10px;border-radius:12px;font-size:12px">{r['verdict_short']}</span></td>
            <td>{len(r['keywords'])}</td>
            <td>{len(r['suspicious_urls'])}</td>
            <td>{len(r['spoofing_flags'])}</td>
        </tr>"""

        kw_list = "".join(f"<li>{k}</li>" for k in r['keywords'][:8])
        url_list = "".join(f"<li>⚠️ {u['url'][:50]}... → {u['reasons'][0]}</li>" for u in r['suspicious_urls'])
        spoof_list = "".join(f"<li>⚠️ {s}</li>" for s in r['spoofing_flags'])
        att_list = "".join(f"<li>⚠️ {a}</li>" for a in r['attachments']) if r['attachments'] else "<li>None</li>"

        cards += f"""
        <div class="card">
            <div class="card-header" style="border-left: 5px solid {color}">
                <h3>📧 {r['file']}</h3>
                <span class="badge" style="background:{color}">{r['verdict_short']} — {r['score']}/100</span>
            </div>
            <div class="card-body">
                <div class="grid">
                    <div class="section">
                        <h4>📋 Headers</h4>
                        <p><b>From:</b> {r['headers'].get('from','N/A')}</p>
                        <p><b>Subject:</b> {r['headers'].get('subject','N/A')}</p>
                        <p><b>Sender IP:</b> {r['headers'].get('sender_ip','N/A')}</p>
                        <p><b>Reply-To:</b> {r['headers'].get('reply_to','N/A')}</p>
                    </div>
                    <div class="section">
                        <h4>🔑 Keywords ({len(r['keywords'])})</h4>
                        <ul>{kw_list if kw_list else '<li>None</li>'}</ul>
                    </div>
                    <div class="section">
                        <h4>🔗 Suspicious URLs ({len(r['suspicious_urls'])})</h4>
                        <ul>{url_list if url_list else '<li>None</li>'}</ul>
                    </div>
                    <div class="section">
                        <h4>🕵️ Spoofing ({len(r['spoofing_flags'])})</h4>
                        <ul>{spoof_list if spoof_list else '<li>None detected</li>'}</ul>
                        <h4>📎 Attachments</h4>
                        <ul>{att_list}</ul>
                    </div>
                </div>
            </div>
        </div>"""

    total = len(results)
    high  = sum(1 for r in results if r['verdict_short'] == 'HIGH RISK')
    susp  = sum(1 for r in results if r['verdict_short'] == 'SUSPICIOUS')
    safe  = sum(1 for r in results if r['verdict_short'] == 'SAFE')

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Phishing Email Analysis Report</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Syne:wght@400;700;800&display=swap');
  :root {{
    --bg: #0a0e1a;
    --surface: #111827;
    --border: #1f2937;
    --text: #e2e8f0;
    --muted: #6b7280;
    --red: #ff4444;
    --orange: #ff9900;
    --green: #00cc44;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Syne', sans-serif; padding: 40px 20px; }}
  .header {{ text-align: center; margin-bottom: 40px; }}
  .header h1 {{ font-size: 2.5rem; font-weight: 800; letter-spacing: -1px; }}
  .header h1 span {{ color: var(--red); }}
  .header p {{ color: var(--muted); margin-top: 8px; font-family: 'JetBrains Mono', monospace; font-size: 13px; }}
  .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 40px; max-width: 900px; margin-left: auto; margin-right: auto; }}
  .stat {{ background: var(--surface); border: 1px solid var(--border); border-radius: 12px; padding: 20px; text-align: center; }}
  .stat .num {{ font-size: 2.5rem; font-weight: 800; }}
  .stat .label {{ color: var(--muted); font-size: 13px; margin-top: 4px; font-family: 'JetBrains Mono', monospace; }}
  .table-wrap {{ background: var(--surface); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; margin-bottom: 40px; max-width: 1100px; margin-left: auto; margin-right: auto; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{ background: #1f2937; padding: 12px 16px; text-align: left; color: var(--muted); font-family: 'JetBrains Mono', monospace; font-weight: 400; letter-spacing: 1px; text-transform: uppercase; font-size: 11px; }}
  td {{ padding: 12px 16px; border-top: 1px solid var(--border); vertical-align: middle; }}
  tr:hover td {{ background: rgba(255,255,255,0.02); }}
  .badge {{ padding: 3px 10px; border-radius: 20px; color: white; font-size: 11px; font-weight: 700; font-family: 'JetBrains Mono', monospace; }}
  .cards {{ max-width: 1100px; margin: 0 auto; display: flex; flex-direction: column; gap: 24px; }}
  .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 12px; overflow: hidden; }}
  .card-header {{ padding: 20px 24px; display: flex; justify-content: space-between; align-items: center; background: rgba(255,255,255,0.02); }}
  .card-header h3 {{ font-size: 1rem; font-weight: 700; }}
  .card-body {{ padding: 24px; }}
  .grid {{ display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; }}
  .section h4 {{ font-size: 13px; color: var(--muted); margin-bottom: 10px; font-family: 'JetBrains Mono', monospace; text-transform: uppercase; letter-spacing: 1px; }}
  .section p {{ font-size: 13px; margin-bottom: 6px; color: #94a3b8; word-break: break-all; }}
  .section p b {{ color: var(--text); }}
  .section ul {{ list-style: none; padding: 0; }}
  .section ul li {{ font-size: 12px; color: #94a3b8; padding: 3px 0; font-family: 'JetBrains Mono', monospace; border-bottom: 1px solid var(--border); word-break: break-all; }}
  h2 {{ max-width: 1100px; margin: 0 auto 20px; font-size: 1.2rem; font-weight: 700; }}
</style>
</head>
<body>
<div class="header">
  <h1>📧 Phishing <span>Email</span> Analyzer</h1>
  <p>SOC L1 Portfolio Project — Generated {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
</div>

<div class="stats">
  <div class="stat"><div class="num">{total}</div><div class="label">Emails Analyzed</div></div>
  <div class="stat"><div class="num" style="color:#ff4444">{high}</div><div class="label">High Risk</div></div>
  <div class="stat"><div class="num" style="color:#ff9900">{susp}</div><div class="label">Suspicious</div></div>
  <div class="stat"><div class="num" style="color:#00cc44">{safe}</div><div class="label">Safe</div></div>
</div>

<h2>📊 Summary Table</h2>
<div class="table-wrap">
<table>
  <thead><tr>
    <th>File</th><th>From</th><th>Subject</th><th>Sender IP</th>
    <th>Score</th><th>Verdict</th><th>Keywords</th><th>Susp. URLs</th><th>Spoofing</th>
  </tr></thead>
  <tbody>{rows}</tbody>
</table>
</div>

<h2>🔍 Detailed Analysis</h2>
<div class="cards">{cards}</div>
</body>
</html>"""

    with open(HTML_REPORT, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"🌐 HTML report saved → {HTML_REPORT}")


# ─────────────────────────────────────────────
# 🚀 MAIN
# ─────────────────────────────────────────────
def main():
    print("\n📧 Starting Phishing Email Analyzer...")
    print(f"   Timestamp: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"   Scanning folder: {EMAILS_FOLDER}/\n")

    # Find all .eml files
    email_files = [f for f in os.listdir(EMAILS_FOLDER) if f.endswith('.eml')]
    if not email_files:
        print("❌ No .eml files found in emails/ folder!")
        return

    print(f"   Found {len(email_files)} email(s) to analyze\n")

    results = []

    for filename in email_files:
        filepath = os.path.join(EMAILS_FOLDER, filename)
        print(f"🔍 Analyzing: {filename}")

        content  = read_email(filepath)
        if not content:
            continue

        headers        = extract_headers(content)
        urls           = extract_urls(content)
        keywords       = check_keywords(content)
        attachments    = check_attachments(content)
        spoofing_flags = detect_spoofing(headers)
        suspicious_urls= analyze_urls(urls)

        score, verdict, verdict_short, reasons = calculate_risk(
            keywords, suspicious_urls, spoofing_flags, attachments
        )

        print_report(filename, headers, keywords, suspicious_urls,
                     spoofing_flags, attachments, score, verdict, reasons)

        results.append({
            'file': filename,
            'headers': headers,
            'keywords': keywords,
            'suspicious_urls': suspicious_urls,
            'spoofing_flags': spoofing_flags,
            'attachments': attachments,
            'score': score,
            'verdict': verdict,
            'verdict_short': verdict_short,
            'reasons': reasons
        })

    # Save reports
    print("="*65)
    save_csv(results)
    save_html(results)
    print(f"\n✅ Analysis complete! {len(results)} email(s) analyzed.\n")


if __name__ == "__main__":
    main()
