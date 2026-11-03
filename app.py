import base64
import csv
from datetime import datetime, timezone
import email
from email import policy
from email.utils import parseaddr
import hashlib
import os
import re
from flask import Flask, redirect, render_template, request, url_for
import requests

app = Flask(__name__)
csv_file = "triage_database.csv"

# --- CONFIGURATION (Your Live API Keys) ---
ABUSEIPDB_API_KEY = (
    "YOUR ABUSEIPDB API KEY"
)
VIRUSTOTAL_API_KEY = (
    "YOUR VIRUSTOTAL API KEY"
)


def defang_url(url):
  return url.replace("http", "hxxp").replace(".", "[.]")


def check_abuseipdb(ip_address):
  if (
      not ip_address
      or ip_address == "Not Found"
      or ip_address.startswith("10.")
      or ip_address.startswith("192.168.")
      or ip_address.startswith("127.")
      or (ip_address.startswith("172.") and 16 <= int(ip_address.split(".")[1]) <= 31)
  ):
    return f"Private/Local IP ({ip_address}) - Skipped Public Check"
  
  url = "https://api.abuseipdb.com/api/v2/check"
  headers = {"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"}
  try:
    print(f"\n[LIVE API CALL] Querying AbuseIPDB for IP: {ip_address}...")
    resp = requests.get(
        url,
        headers=headers,
        params={"ipAddress": ip_address, "maxAgeInDays": "90"},
        timeout=5,
    )
    print(f"[ABUSEIPDB RESPONSE] HTTP Status Code: {resp.status_code}")
    if resp.status_code == 200:
      data = resp.json()["data"]
      score = data.get("abuseConfidenceScore", 0)
      reports = data.get("totalReports", 0)
      print(f"[ABUSEIPDB DATA] Score: {score}%, Reports: {reports}")
      return f"Abuse Score: {score}% (Reports: {reports})"
    else:
      print(f"[ABUSEIPDB ERROR] Response body: {resp.text}")
  except Exception as e:
    print(f"[ABUSEIPDB EXCEPTION] {str(e)}")
  return "Check Failed / Skipped"


def check_virustotal_url(target_url):
  if not target_url:
    return "URL Not Found / Skipped"
  url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
  headers = {"x-apikey": VIRUSTOTAL_API_KEY}
  try:
    print(f"\n[LIVE API CALL] Querying VirusTotal v3 for URL...")
    resp = requests.get(
        f"https://www.virustotal.com/api/v3/urls/{url_id}",
        headers=headers,
        timeout=5,
    )
    print(f"[VIRUSTOTAL URL RESPONSE] HTTP Status Code: {resp.status_code}")
    if resp.status_code == 200:
      stats = (
          resp.json()
          .get("data", {})
          .get("attributes", {})
          .get("last_analysis_stats", {})
      )
      mal = stats.get("malicious", 0)
      susp = stats.get("suspicious", 0)
      print(f"[VIRUSTOTAL URL DATA] Malicious: {mal}, Suspicious: {susp}")
      return f"Malicious: {mal}, Suspicious: {susp}"
    elif resp.status_code == 404:
      return "URL not previously scanned in VT database"
    else:
      return f"Error: HTTP {resp.status_code}"
  except Exception as e:
    return "Check Failed / Skipped"


def check_virustotal_file(file_hash):
  if not file_hash:
    return "Hash Not Found / Skipped"
  headers = {"x-apikey": VIRUSTOTAL_API_KEY}
  try:
    print(f"\n[LIVE API CALL] Querying VirusTotal v3 for File Hash: {file_hash}...")
    resp = requests.get(
        f"https://www.virustotal.com/api/v3/files/{file_hash}",
        headers=headers,
        timeout=5,
    )
    print(f"[VIRUSTOTAL FILE RESPONSE] HTTP Status Code: {resp.status_code}")
    if resp.status_code == 200:
      stats = (
          resp.json()
          .get("data", {})
          .get("attributes", {})
          .get("last_analysis_stats", {})
      )
      mal = stats.get("malicious", 0)
      susp = stats.get("suspicious", 0)
      print(f"[VIRUSTOTAL FILE DATA] Malicious: {mal}, Suspicious: {susp}")
      return f"Malicious: {mal}, Suspicious: {susp}"
    elif resp.status_code == 404:
      return "File hash not previously scanned in VT database"
    else:
      return f"Error: HTTP {resp.status_code}"
  except Exception as e:
    return "Check Failed / Skipped"


@app.route("/", methods=["GET"])
def index():
  return render_template("index.html", report=None)


@app.route("/analyze", methods=["POST"])
def analyze():
  raw_email_text = request.form.get("email_content", "")

  msg = email.message_from_string(raw_email_text, policy=email.policy.default)

  date_time = msg.get(
      "Date", datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
  )
  subject = msg.get("Subject", "No Subject")

  # Parse sender and recipient details cleanly with smart fallbacks
  raw_from = msg.get("From", "Unknown")
  raw_to = msg.get("To", "Unknown")

  parsed_sender_name, sender_email = parseaddr(raw_from)
  parsed_recipient_name, recipient_email = parseaddr(raw_to)

  sender_name = (
      parsed_sender_name
      if parsed_sender_name
      else (sender_email.split("@")[0] if sender_email else "Unknown")
  )
  recipient_name = (
      parsed_recipient_name
      if parsed_recipient_name
      else (recipient_email.split("@")[0] if recipient_email else "Unknown")
  )

  reply_to = msg.get("Reply-To", raw_from)

  # --- CLEAN PASS/FAIL AUTH PARSING ---
  auth_str = msg.get("Authentication-Results", "").lower()
  
  spf_match = re.search(r"spf=(\w+)", auth_str)
  dkim_match = re.search(r"dkim=(\w+)", auth_str)
  dmarc_match = re.search(r"dmarc=(\w+)", auth_str)

  spf_status = spf_match.group(1).upper() if spf_match else "NOT FOUND"
  dkim_status = dkim_match.group(1).upper() if dkim_match else "NOT FOUND"
  dmarc_status = dmarc_match.group(1).upper() if dmarc_match else "NOT FOUND"

  auth_summary = f"SPF: {spf_status} | DKIM: {dkim_status} | DMARC: {dmarc_status}"

  # --- ROBUST IP EXTRACTION AT ANY COST ---
  received_hops = msg.get_all("Received", [])
  public_ips = []
  private_ips = []
  ip_pattern = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"

  for hop in reversed(received_hops):
    bracketed = re.findall(r"\[(" + ip_pattern + r")\]", hop)
    for ip in bracketed:
      if (
          ip.startswith("10.")
          or ip.startswith("192.168.")
          or ip.startswith("127.")
          or (ip.startswith("172.") and 16 <= int(ip.split(".")[1]) <= 31)
      ):
        if ip not in private_ips:
          private_ips.append(ip)
      else:
        if ip not in public_ips:
          public_ips.append(ip)

    all_ips = re.findall(ip_pattern, hop)
    for ip in all_ips:
      if ip not in public_ips and ip not in private_ips:
        if (
            ip.startswith("10.")
            or ip.startswith("192.168.")
            or ip.startswith("127.")
            or (ip.startswith("172.") and 16 <= int(ip.split(".")[1]) <= 31)
        ):
          private_ips.append(ip)
        else:
          public_ips.append(ip)

  if not public_ips and not private_ips:
    all_text_ips = re.findall(ip_pattern, raw_email_text)
    for ip in all_text_ips:
      if (
          ip.startswith("10.")
          or ip.startswith("192.168.")
          or ip.startswith("127.")
          or (ip.startswith("172.") and 16 <= int(ip.split(".")[1]) <= 31)
      ):
        private_ips.append(ip)
      else:
        public_ips.append(ip)

  originating_ip = (
      public_ips[0]
      if public_ips
      else (private_ips[0] if private_ips else "Not Found")
  )

  recipient_ip = "Not Found"
  if received_hops:
    top_bracketed = re.findall(r"\[(" + ip_pattern + r")\]", received_hops[0])
    if top_bracketed:
      recipient_ip = top_bracketed[0]
    else:
      top_ips = re.findall(ip_pattern, received_hops[0])
      if top_ips:
        recipient_ip = top_ips[0]

  ip_rep = check_abuseipdb(originating_ip)

  # Extract body
  body_text = ""
  if msg.is_multipart():
    for part in msg.walk():
      if part.get_content_type() in ["text/plain", "text/html"]:
        payload = part.get_payload(decode=True)
        if payload:
          body_text += payload.decode("utf-8", errors="ignore") + "\n"
  else:
    payload = msg.get_payload(decode=True)
    if payload:
      body_text = payload.decode("utf-8", errors="ignore")

  if not body_text.strip():
    body_text = raw_email_text

  # URLs
  urls = re.findall(r"https?://[^\s<>\"'()]+|www\.[^\s<>\"'()]+", body_text)
  url_data_list = []
  for u in set(urls):
    vt_res = check_virustotal_url(u)
    url_data_list.append({
        "defanged": defang_url(u),
        "sha256": hashlib.sha256(u.encode("utf-8")).hexdigest(),
        "vt_result": vt_res,
    })

  # Attachments & VT File Hash Check
  attachments = []
  for part in msg.walk():
    if part.get_content_maintype() == "multipart":
      continue
    filename = part.get_filename()
    if filename:
      file_data = part.get_payload(decode=True)
      if file_data:
        file_sha256 = hashlib.sha256(file_data).hexdigest()
        vt_file_res = check_virustotal_file(file_sha256)
        attachments.append({
            "filename": filename,
            "size": round(len(file_data) / 1024, 2),
            "sha256": file_sha256,
            "vt_result": vt_file_res,
        })

  # --- DYNAMIC RISK CALCULATOR ---
  risk_level = "LOW RISK"

  if "Abuse Score:" in ip_rep:
    try:
      score_val = int(re.search(r"(\d+)%", ip_rep).group(1))
      if score_val >= 50:
        risk_level = "HIGH RISK"
      elif score_val > 0:
        risk_level = "MEDIUM RISK"
    except:
      pass

  for u in url_data_list:
    if "Malicious:" in u["vt_result"]:
      try:
        mal_val = int(
            re.search(r"Malicious:\s*(\d+)", u["vt_result"]).group(1)
        )
        if mal_val > 0:
          risk_level = "HIGH RISK"
          break
      except:
        pass

  for att in attachments:
    if "Malicious:" in att["vt_result"]:
      try:
        mal_val = int(
            re.search(r"Malicious:\s*(\d+)", att["vt_result"]).group(1)
        )
        if mal_val > 0:
          risk_level = "HIGH RISK"
          break
      except:
        pass

  report_data = {
      "timestamp": date_time,
      "subject": subject,
      "sender_name": sender_name,
      "sender_email": sender_email if sender_email else raw_from,
      "recipient_name": recipient_name,
      "recipient_email": recipient_email if recipient_email else raw_to,
      "recipient_ip": recipient_ip,
      "originating_ip": originating_ip,
      "ip_reputation": ip_rep,
      "reply_to": reply_to,
      "auth_results": auth_summary,
      "url_count": len(url_data_list),
      "attachment_count": len(attachments),
      "risk_status": risk_level,
      "urls": url_data_list,
      "attachments": attachments,
  }

  return render_template("index.html", report=report_data)


@app.route("/save", methods=["POST"])
def save():
  file_exists = os.path.exists(csv_file)
  with open(csv_file, mode="a", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    if not file_exists:
      writer.writerow([
          "Timestamp",
          "Subject",
          "Sender",
          "Recipient",
          "Originating IP",
          "IP Reputation",
          "URL Count",
          "Attachment Count",
          "Risk Status",
      ])
    writer.writerow([
        request.form.get("timestamp"),
        request.form.get("subject"),
        request.form.get("sender_email"),
        request.form.get("recipient_email"),
        request.form.get("originating_ip"),
        request.form.get("ip_reputation"),
        request.form.get("url_count"),
        request.form.get("attachment_count"),
        request.form.get("risk_status"),
    ])
  return render_template(
      "index.html",
      report=None,
      success_message="Successfully saved record to triage_database.csv!",
  )


if __name__ == "__main__":
  app.run(debug=True, port=5000)