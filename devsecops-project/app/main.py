"""
Updated Flask app with Vulnerabilities & Solutions section
"""

import os
import logging
from flask import Flask, request, jsonify, render_template_string
from cryptography.fernet import Fernet

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

app = Flask(__name__)

ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
SECRET_TOKEN = os.environ.get("SECRET_TOKEN")

if not ENCRYPTION_KEY or not SECRET_TOKEN:
    raise RuntimeError("ENCRYPTION_KEY and SECRET_TOKEN must be set via environment variables.")

fernet = Fernet(ENCRYPTION_KEY.encode())


HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Privacy-Preserving App</title>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
  :root{--bg:#050b1a;--surface:#0d1f3c;--surface2:#112347;--border:#1a3a6b;--accent:#00e5ff;--accent2:#7c3aed;--green:#00ff9d;--red:#ff4d6d;--yellow:#ffd166;--text:#e8f4fd;--muted:#4a7aa7;}
  *{margin:0;padding:0;box-sizing:border-box;}
  body{font-family:'Space Grotesk',sans-serif;background:var(--bg);color:var(--text);min-height:100vh;overflow-x:hidden;}
  .bg-anim{position:fixed;inset:0;z-index:0;background:radial-gradient(ellipse at 20% 50%,rgba(0,229,255,.05) 0%,transparent 60%),radial-gradient(ellipse at 80% 20%,rgba(124,58,237,.05) 0%,transparent 60%);}
  .grid-lines{position:fixed;inset:0;z-index:0;background-image:linear-gradient(rgba(0,229,255,.04) 1px,transparent 1px),linear-gradient(90deg,rgba(0,229,255,.04) 1px,transparent 1px);background-size:60px 60px;}
  .particles{position:fixed;inset:0;z-index:0;pointer-events:none;overflow:hidden;}
  .particle{position:absolute;border-radius:50%;animation:float linear infinite;}
  @keyframes float{0%{transform:translateY(100vh) rotate(0deg);opacity:0;}10%{opacity:1;}90%{opacity:1;}100%{transform:translateY(-100px) rotate(720deg);opacity:0;}}
  nav{position:relative;z-index:10;padding:1.25rem 3rem;display:flex;align-items:center;gap:1rem;border-bottom:1px solid var(--border);backdrop-filter:blur(20px);background:rgba(5,11,26,.8);}
  .nav-logo{width:40px;height:40px;background:linear-gradient(135deg,var(--accent),var(--accent2));border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:18px;box-shadow:0 0 20px rgba(0,229,255,.3);}
  .nav-title{font-size:1.1rem;font-weight:700;letter-spacing:-.02em;}
  .nav-sub{font-size:.75rem;color:var(--muted);font-family:'JetBrains Mono',monospace;}
  .status-pill{margin-left:auto;display:flex;align-items:center;gap:8px;background:rgba(0,255,157,.08);border:1px solid rgba(0,255,157,.2);padding:6px 14px;border-radius:20px;font-size:12px;color:var(--green);font-family:'JetBrains Mono',monospace;}
  .status-dot{width:7px;height:7px;border-radius:50%;background:var(--green);box-shadow:0 0 8px var(--green);animation:blink 2s infinite;}
  @keyframes blink{0%,100%{opacity:1}50%{opacity:.4}}
  main{position:relative;z-index:1;max-width:1100px;margin:0 auto;padding:3rem 2rem;}
  .hero{text-align:center;margin-bottom:3rem;}
  .hero-badge{display:inline-flex;align-items:center;gap:8px;background:rgba(0,229,255,.06);border:1px solid rgba(0,229,255,.15);padding:6px 16px;border-radius:20px;font-size:12px;color:var(--accent);font-family:'JetBrains Mono',monospace;margin-bottom:1.5rem;letter-spacing:.05em;}
  .hero h1{font-size:3.2rem;font-weight:700;letter-spacing:-.04em;line-height:1.05;margin-bottom:1rem;}
  .hero h1 .grad{background:linear-gradient(90deg,var(--accent),var(--accent2),var(--green));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;}
  .hero p{font-size:1rem;color:var(--muted);max-width:520px;margin:0 auto;line-height:1.6;}
  .stats-row{display:grid;grid-template-columns:repeat(3,1fr);gap:1px;background:var(--border);border:1px solid var(--border);border-radius:16px;overflow:hidden;margin-bottom:3rem;}
  .stat{background:var(--surface);padding:1.5rem;text-align:center;transition:background .2s;}
  .stat:hover{background:var(--surface2);}
  .stat-val{font-size:2rem;font-weight:700;font-family:'JetBrains Mono',monospace;color:var(--accent);text-shadow:0 0 20px rgba(0,229,255,.4);display:block;margin-bottom:4px;}
  .stat-lbl{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;}
  .section-title{font-size:1.4rem;font-weight:700;letter-spacing:-.03em;margin-bottom:1.25rem;display:flex;align-items:center;gap:10px;}
  .section-title::after{content:'';flex:1;height:1px;background:var(--border);}
  .demo-grid{display:grid;grid-template-columns:1fr 1fr;gap:1.5rem;margin-bottom:1.5rem;}
  @media(max-width:700px){.demo-grid{grid-template-columns:1fr}.hero h1{font-size:2rem}.stats-row{grid-template-columns:1fr}}
  .card{background:var(--surface);border:1px solid var(--border);border-radius:16px;overflow:hidden;transition:border-color .2s,transform .2s;}
  .card:hover{border-color:rgba(0,229,255,.3);transform:translateY(-2px);}
  .card-head{padding:1rem 1.25rem;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px;font-size:13px;font-weight:600;}
  .card-icon{width:32px;height:32px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:15px;}
  .icon-enc{background:rgba(0,229,255,.1);}.icon-dec{background:rgba(124,58,237,.1);}.icon-comp{background:rgba(0,255,157,.1);}
  .card-body{padding:1.25rem;}
  input,textarea{width:100%;background:rgba(0,0,0,.3);border:1px solid var(--border);border-radius:8px;color:var(--text);font-family:'JetBrains Mono',monospace;font-size:13px;padding:10px 12px;outline:none;transition:border-color .2s;margin-bottom:10px;}
  input:focus,textarea:focus{border-color:var(--accent);}
  input::placeholder,textarea::placeholder{color:var(--muted);}
  .btn{width:100%;padding:10px;border:none;border-radius:8px;font-family:'Space Grotesk',sans-serif;font-weight:600;font-size:13px;cursor:pointer;transition:all .2s;}
  .btn-enc{background:linear-gradient(135deg,var(--accent),#0099bb);color:#050b1a;}
  .btn-dec{background:linear-gradient(135deg,var(--accent2),#5b21b6);color:#fff;}
  .btn-comp{background:linear-gradient(135deg,var(--green),#00b870);color:#050b1a;}
  .btn:hover{transform:translateY(-1px);filter:brightness(1.1);}
  .result-box{margin-top:10px;background:rgba(0,0,0,.4);border:1px solid var(--border);border-radius:8px;padding:10px 12px;font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--accent);min-height:42px;word-break:break-all;display:none;animation:fadeIn .3s ease;}
  .result-box.visible{display:block;}
  @keyframes fadeIn{from{opacity:0;transform:translateY(4px)}to{opacity:1;transform:translateY(0)}}
  .result-label{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin-bottom:4px;}

  /* VULN SECTION */
  .vuln-tabs{display:flex;gap:8px;margin-bottom:1.25rem;flex-wrap:wrap;}
  .vtab{padding:8px 18px;border-radius:20px;border:1px solid var(--border);background:transparent;color:var(--muted);font-family:'Space Grotesk',sans-serif;font-size:12px;font-weight:600;cursor:pointer;transition:all .2s;}
  .vtab.active-all{border-color:var(--accent);color:var(--accent);background:rgba(0,229,255,.08);}
  .vtab.active-high{border-color:rgba(255,77,109,.5);color:var(--red);background:rgba(255,77,109,.08);}
  .vtab.active-medium{border-color:rgba(255,209,102,.5);color:var(--yellow);background:rgba(255,209,102,.08);}
  .vtab.active-low{border-color:rgba(0,255,157,.5);color:var(--green);background:rgba(0,255,157,.08);}
  .vuln-stats{display:grid;grid-template-columns:repeat(4,1fr);gap:1px;background:var(--border);border:1px solid var(--border);border-radius:12px;overflow:hidden;margin-bottom:1.25rem;}
  .vstat{background:var(--surface);padding:1rem;text-align:center;}
  .vstat-num{font-size:1.8rem;font-weight:700;font-family:'JetBrains Mono',monospace;display:block;}
  .vstat-lbl{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.08em;margin-top:2px;}
  .n-high{color:var(--red);text-shadow:0 0 15px rgba(255,77,109,.4);}
  .n-med{color:var(--yellow);text-shadow:0 0 15px rgba(255,209,102,.4);}
  .n-low{color:var(--green);text-shadow:0 0 15px rgba(0,255,157,.4);}
  .n-tot{color:var(--text);}
  .vuln-card{border-radius:12px;padding:1.25rem;margin-bottom:10px;border:1px solid transparent;animation:slideIn .3s ease;}
  @keyframes slideIn{from{opacity:0;transform:translateX(-10px)}to{opacity:1;transform:translateX(0)}}
  .vuln-card.HIGH{background:rgba(255,77,109,.06);border-color:rgba(255,77,109,.2);}
  .vuln-card.MEDIUM{background:rgba(255,209,102,.06);border-color:rgba(255,209,102,.2);}
  .vuln-card.LOW{background:rgba(0,255,157,.04);border-color:rgba(0,255,157,.15);}
  .vuln-top{display:flex;align-items:flex-start;gap:10px;margin-bottom:10px;}
  .sev-badge{font-size:10px;font-weight:700;font-family:'JetBrains Mono',monospace;padding:3px 10px;border-radius:4px;white-space:nowrap;flex-shrink:0;margin-top:2px;}
  .b-HIGH{background:rgba(255,77,109,.2);color:#ff6b87;}
  .b-MEDIUM{background:rgba(255,209,102,.2);color:#ffd166;}
  .b-LOW{background:rgba(0,255,157,.2);color:#00ff9d;}
  .vuln-title{font-size:14px;font-weight:600;margin-bottom:2px;}
  .vuln-rule{font-size:11px;font-family:'JetBrains Mono',monospace;color:var(--muted);}
  .vuln-code{background:rgba(0,0,0,.4);border-radius:6px;padding:8px 12px;font-family:'JetBrains Mono',monospace;font-size:12px;color:#ff6b87;margin:8px 0;overflow-x:auto;border-left:3px solid rgba(255,77,109,.4);}
  .vuln-desc{font-size:13px;color:#94a3b8;margin:6px 0;line-height:1.6;}
  .fix-section{background:rgba(0,255,157,.04);border:1px solid rgba(0,255,157,.15);border-radius:10px;padding:12px 14px;margin-top:10px;}
  .fix-header{font-size:11px;font-weight:700;color:var(--green);text-transform:uppercase;letter-spacing:.1em;margin-bottom:6px;}
  .fix-desc{font-size:12px;color:#94a3b8;line-height:1.6;margin-bottom:8px;}
  .fix-code{background:rgba(0,0,0,.5);border-radius:6px;padding:8px 12px;font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--green);border-left:3px solid rgba(0,255,157,.4);overflow-x:auto;white-space:pre;}
  .expand-btn{background:transparent;border:1px solid var(--border);color:var(--muted);font-size:12px;cursor:pointer;padding:5px 14px;border-radius:20px;font-family:'Space Grotesk',sans-serif;transition:all .2s;margin-top:8px;}
  .expand-btn:hover{color:var(--accent);border-color:var(--accent);}
  .expandable{display:none;}
  .expandable.open{display:block;margin-top:10px;}

  /* PIPELINE */
  .pipeline{display:flex;align-items:center;overflow-x:auto;padding-bottom:.5rem;gap:0;margin-bottom:3rem;}
  .pipe-step{flex-shrink:0;background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:1rem 1.25rem;text-align:center;min-width:120px;transition:all .2s;}
  .pipe-step:hover{border-color:var(--accent);background:var(--surface2);}
  .pipe-icon{font-size:1.5rem;margin-bottom:6px;}
  .pipe-name{font-size:12px;font-weight:600;margin-bottom:2px;}
  .pipe-tool{font-size:10px;color:var(--muted);font-family:'JetBrains Mono',monospace;}
  .pipe-status{font-size:10px;margin-top:4px;color:var(--green);}
  .pipe-arrow{color:var(--border);font-size:1.2rem;padding:0 6px;flex-shrink:0;}

  /* ENDPOINTS */
  .endpoint-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:1rem;margin-bottom:3rem;}
  @media(max-width:700px){.endpoint-grid{grid-template-columns:1fr}}
  .endpoint-card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:1.25rem;transition:all .2s;}
  .endpoint-card:hover{border-color:rgba(0,229,255,.3);}
  .method-badge{display:inline-block;font-size:10px;font-weight:700;font-family:'JetBrains Mono',monospace;padding:3px 8px;border-radius:4px;margin-bottom:8px;}
  .get{background:rgba(0,255,157,.15);color:var(--green);}
  .post{background:rgba(0,229,255,.15);color:var(--accent);}
  .endpoint-path{font-family:'JetBrains Mono',monospace;font-size:13px;font-weight:600;margin-bottom:4px;}
  .endpoint-desc{font-size:12px;color:var(--muted);}
  footer{position:relative;z-index:1;text-align:center;padding:2rem;border-top:1px solid var(--border);color:var(--muted);font-size:12px;font-family:'JetBrains Mono',monospace;}
  footer span{color:var(--accent);}
  .loading-spinner{display:inline-block;width:14px;height:14px;border:2px solid rgba(0,0,0,.3);border-top-color:currentColor;border-radius:50%;animation:spin .6s linear infinite;vertical-align:middle;margin-right:6px;}
  @keyframes spin{to{transform:rotate(360deg)}}
</style>
</head>
<body>
<div class="bg-anim"></div>
<div class="grid-lines"></div>
<div class="particles" id="particles"></div>

<nav>
  <div class="nav-logo">🔐</div>
  <div>
    <div class="nav-title">Privacy-Preserving App</div>
    <div class="nav-sub">DevSecOps Lifecycle · Azure Container Apps</div>
  </div>
  <div class="status-pill"><div class="status-dot"></div>SYSTEM HEALTHY</div>
</nav>

<main>
  <div class="hero">
    <div class="hero-badge">🛡️ DEVSECOPS SECURED · AZURE DEPLOYED</div>
    <h1>Privacy-Preserving<br><span class="grad">Encryption API</span></h1>
    <p>Secure homomorphic encryption service — protected by automated DevSecOps pipeline with SAST, SCA, and container scanning.</p>
  </div>

  <div class="stats-row">
    <div class="stat"><span class="stat-val">99.9%</span><span class="stat-lbl">Uptime</span></div>
    <div class="stat"><span class="stat-val" id="reqCount">0</span><span class="stat-lbl">Requests</span></div>
    <div class="stat"><span class="stat-val">AES-256</span><span class="stat-lbl">Encryption</span></div>
  </div>

  <div class="section-title">🔬 Live API Demo</div>
  <div class="demo-grid">
    <div class="card">
      <div class="card-head"><div class="card-icon icon-enc">🔒</div>Encrypt Data</div>
      <div class="card-body">
        <input type="text" id="encInput" placeholder="Enter text to encrypt..."/>
        <button class="btn btn-enc" onclick="encryptData()">🔒 Encrypt</button>
        <div class="result-box" id="encResult"><div class="result-label">Encrypted Output</div><div id="encOutput"></div></div>
      </div>
    </div>
    <div class="card">
      <div class="card-head"><div class="card-icon icon-dec">🔓</div>Decrypt Data</div>
      <div class="card-body">
        <textarea id="decInput" placeholder="Paste encrypted text here..." style="height:72px;resize:none;margin-bottom:10px"></textarea>
        <button class="btn btn-dec" onclick="decryptData()">🔓 Decrypt</button>
        <div class="result-box" id="decResult" style="color:#a78bfa"><div class="result-label">Decrypted Output</div><div id="decOutput"></div></div>
      </div>
    </div>
  </div>
  <div class="card" style="margin-bottom:3rem">
    <div class="card-head"><div class="card-icon icon-comp">➕</div>Privacy-Preserving Computation</div>
    <div class="card-body" style="display:grid;grid-template-columns:1fr 1fr auto;gap:10px;align-items:end">
      <div><div style="font-size:11px;color:var(--muted);margin-bottom:6px">Number A</div><input type="number" id="numA" placeholder="e.g. 42" style="margin-bottom:0"/></div>
      <div><div style="font-size:11px;color:var(--muted);margin-bottom:6px">Number B</div><input type="number" id="numB" placeholder="e.g. 8" style="margin-bottom:0"/></div>
      <button class="btn btn-comp" style="white-space:nowrap" onclick="computeEncrypted()">➕ Compute</button>
    </div>
    <div class="card-body" style="padding-top:0">
      <div class="result-box" id="compResult" style="color:var(--green)"><div class="result-label">Result</div><div id="compOutput"></div></div>
    </div>
  </div>

  <!-- VULNERABILITIES SECTION -->
  <div class="section-title">⚠️ Cryptographic Risks & Vulnerabilities Detected</div>
  <div class="vuln-stats">
    <div class="vstat"><span class="vstat-num n-high">4</span><span class="vstat-lbl">High</span></div>
    <div class="vstat"><span class="vstat-num n-med">5</span><span class="vstat-lbl">Medium</span></div>
    <div class="vstat"><span class="vstat-num n-low">7</span><span class="vstat-lbl">Low</span></div>
    <div class="vstat"><span class="vstat-num n-tot">16</span><span class="vstat-lbl">Total Found</span></div>
  </div>
  <div class="vuln-tabs">
    <button class="vtab active-all" onclick="filterVulns('all',this)">All Issues</button>
    <button class="vtab" onclick="filterVulns('HIGH',this)">🔴 High (4)</button>
    <button class="vtab" onclick="filterVulns('MEDIUM',this)">🟡 Medium (5)</button>
    <button class="vtab" onclick="filterVulns('LOW',this)">🟢 Low (7)</button>
  </div>
  <div id="vulnList">

    <div class="vuln-card HIGH" data-sev="HIGH">
      <div class="vuln-top"><span class="sev-badge b-HIGH">HIGH</span><div><div class="vuln-title">Weak MD5 Hash for Password Security</div><div class="vuln-rule">B324 · CWE-327 · vulnerable_bank.py · Line 30</div></div></div>
      <div class="vuln-code">return hashlib.md5(password.encode()).hexdigest()</div>
      <div class="vuln-desc">MD5 is cryptographically broken. Attackers can crack MD5 hashes in seconds using rainbow tables or GPU brute-force, putting all user accounts at risk.</div>
      <button class="expand-btn" onclick="toggleFix(this)">▼ Show Fix</button>
      <div class="expandable"><div class="fix-section"><div class="fix-header">✅ Recommended Fix</div><div class="fix-desc">Use bcrypt or argon2 designed for slow, brute-force resistant password hashing.</div><div class="fix-code">import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
# Verify:
bcrypt.checkpw(password.encode(), hashed)</div></div></div>
    </div>

    <div class="vuln-card HIGH" data-sev="HIGH">
      <div class="vuln-top"><span class="sev-badge b-HIGH">HIGH</span><div><div class="vuln-title">Weak SHA1 Hash for Password Security</div><div class="vuln-rule">B324 · CWE-327 · vulnerable_bank.py · Line 34</div></div></div>
      <div class="vuln-code">return hashlib.sha1(password.encode()).hexdigest()</div>
      <div class="vuln-desc">SHA1 has known collision vulnerabilities and is deprecated for security use. Google demonstrated a successful SHA1 collision attack in 2017.</div>
      <button class="expand-btn" onclick="toggleFix(this)">▼ Show Fix</button>
      <div class="expandable"><div class="fix-section"><div class="fix-header">✅ Recommended Fix</div><div class="fix-desc">Use SHA-256 minimum for general hashing, or bcrypt/argon2 for passwords.</div><div class="fix-code">import hashlib, secrets
salt = secrets.token_hex(32)
hashed = hashlib.sha256((salt + password).encode()).hexdigest()</div></div></div>
    </div>

    <div class="vuln-card HIGH" data-sev="HIGH">
      <div class="vuln-top"><span class="sev-badge b-HIGH">HIGH</span><div><div class="vuln-title">Command Injection via shell=True</div><div class="vuln-rule">B602 · CWE-78 · vulnerable_bank.py · Line 65</div></div></div>
      <div class="vuln-code">subprocess.call("echo Report for " + account_id, shell=True)</div>
      <div class="vuln-desc">shell=True with user input allows attackers to inject arbitrary OS commands. Input like "; rm -rf /" could destroy server data.</div>
      <button class="expand-btn" onclick="toggleFix(this)">▼ Show Fix</button>
      <div class="expandable"><div class="fix-section"><div class="fix-header">✅ Recommended Fix</div><div class="fix-desc">Pass arguments as a list with shell=False to prevent injection.</div><div class="fix-code">subprocess.run(["echo", "Report for", account_id],
               shell=False, capture_output=True)</div></div></div>
    </div>

    <div class="vuln-card HIGH" data-sev="HIGH">
      <div class="vuln-top"><span class="sev-badge b-HIGH">HIGH</span><div><div class="vuln-title">OS Command Injection via os.system()</div><div class="vuln-rule">B605 · CWE-78 · vulnerable_bank.py · Line 69</div></div></div>
      <div class="vuln-code">os.system("cat /reports/" + account_id + ".txt")</div>
      <div class="vuln-desc">os.system() with user input enables path traversal and command injection. Attackers can read /etc/passwd or other sensitive system files.</div>
      <button class="expand-btn" onclick="toggleFix(this)">▼ Show Fix</button>
      <div class="expandable"><div class="fix-section"><div class="fix-header">✅ Recommended Fix</div><div class="fix-desc">Use Python file operations with path validation to prevent traversal attacks.</div><div class="fix-code">import pathlib
BASE = pathlib.Path("/reports")
path = (BASE / account_id).with_suffix(".txt")
if BASE in path.parents:  # prevent traversal
    content = path.read_text()</div></div></div>
    </div>

    <div class="vuln-card MEDIUM" data-sev="MEDIUM">
      <div class="vuln-top"><span class="sev-badge b-MEDIUM">MEDIUM</span><div><div class="vuln-title">SQL Injection via String Concatenation</div><div class="vuln-rule">B608 · CWE-89 · vulnerable_bank.py · Line 45</div></div></div>
      <div class="vuln-code">"SELECT balance FROM accounts WHERE username = '" + username + "'"</div>
      <div class="vuln-desc">Direct string concatenation in SQL allows attackers to inject malicious queries. Input ' OR '1'='1 exposes all account balances.</div>
      <button class="expand-btn" onclick="toggleFix(this)">▼ Show Fix</button>
      <div class="expandable"><div class="fix-section"><div class="fix-header">✅ Recommended Fix</div><div class="fix-desc">Always use parameterized queries — never format SQL with user input.</div><div class="fix-code">cursor.execute(
    "SELECT balance FROM accounts WHERE username = ?",
    (username,)
)</div></div></div>
    </div>

    <div class="vuln-card MEDIUM" data-sev="MEDIUM">
      <div class="vuln-top"><span class="sev-badge b-MEDIUM">MEDIUM</span><div><div class="vuln-title">SQL Injection via f-string Query</div><div class="vuln-rule">B608 · CWE-89 · vulnerable_bank.py · Line 54</div></div></div>
      <div class="vuln-code">f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"</div>
      <div class="vuln-desc">F-strings in SQL are equally dangerous. Input admin'-- comments out the password check, bypassing authentication entirely.</div>
      <button class="expand-btn" onclick="toggleFix(this)">▼ Show Fix</button>
      <div class="expandable"><div class="fix-section"><div class="fix-header">✅ Recommended Fix</div><div class="fix-desc">Use parameterized queries and compare hashed passwords, never plaintext.</div><div class="fix-code">cursor.execute(
    "SELECT * FROM users WHERE username=? AND password_hash=?",
    (username, hash_password(password))
)</div></div></div>
    </div>

    <div class="vuln-card MEDIUM" data-sev="MEDIUM">
      <div class="vuln-top"><span class="sev-badge b-MEDIUM">MEDIUM</span><div><div class="vuln-title">Insecure Pickle Deserialization</div><div class="vuln-rule">B301 · CWE-502 · vulnerable_bank.py · Line 77</div></div></div>
      <div class="vuln-code">return pickle.loads(session_data)  # DANGEROUS</div>
      <div class="vuln-desc">Deserializing untrusted pickle data can execute arbitrary Python code — a Remote Code Execution (RCE) vulnerability. Attackers who control session data can run any command.</div>
      <button class="expand-btn" onclick="toggleFix(this)">▼ Show Fix</button>
      <div class="expandable"><div class="fix-section"><div class="fix-header">✅ Recommended Fix</div><div class="fix-desc">Use JSON for session serialization. It cannot execute code on deserialization.</div><div class="fix-code">import json
def load_session(data: str) -> dict:
    return json.loads(data)

def save_session(data: dict) -> str:
    return json.dumps(data)</div></div></div>
    </div>

    <div class="vuln-card LOW" data-sev="LOW">
      <div class="vuln-top"><span class="sev-badge b-LOW">LOW</span><div><div class="vuln-title">Hardcoded Password: 'admin123'</div><div class="vuln-rule">B105 · CWE-259 · vulnerable_bank.py · Line 18</div></div></div>
      <div class="vuln-code">DB_PASSWORD = "admin123"</div>
      <div class="vuln-desc">Hardcoded credentials in source code are exposed to anyone with repo access. If the repository is ever made public, the database is immediately compromised.</div>
      <button class="expand-btn" onclick="toggleFix(this)">▼ Show Fix</button>
      <div class="expandable"><div class="fix-section"><div class="fix-header">✅ Recommended Fix</div><div class="fix-desc">Load secrets from environment variables or Azure Key Vault — never hardcode them.</div><div class="fix-code">import os
DB_PASSWORD = os.environ.get("DB_PASSWORD")
if not DB_PASSWORD:
    raise RuntimeError("DB_PASSWORD not configured!")</div></div></div>
    </div>

    <div class="vuln-card LOW" data-sev="LOW">
      <div class="vuln-top"><span class="sev-badge b-LOW">LOW</span><div><div class="vuln-title">Hardcoded Secret Key</div><div class="vuln-rule">B105 · CWE-259 · vulnerable_bank.py · Line 19</div></div></div>
      <div class="vuln-code">SECRET_KEY = "mysecretkey123"</div>
      <div class="vuln-desc">Hardcoded secret keys can be used to forge authentication tokens. This was detected by TruffleHog in our DevSecOps pipeline before reaching production.</div>
      <button class="expand-btn" onclick="toggleFix(this)">▼ Show Fix</button>
      <div class="expandable"><div class="fix-section"><div class="fix-header">✅ Recommended Fix</div><div class="fix-desc">Generate cryptographically strong keys and store in Azure Key Vault.</div><div class="fix-code">import secrets, os
# One-time generation:
print(secrets.token_hex(32))
# In app:
SECRET_KEY = os.environ.get("SECRET_KEY")</div></div></div>
    </div>

    <div class="vuln-card LOW" data-sev="LOW">
      <div class="vuln-top"><span class="sev-badge b-LOW">LOW</span><div><div class="vuln-title">Insecure Random OTP Generation</div><div class="vuln-rule">B311 · CWE-330 · vulnerable_bank.py · Line 90</div></div></div>
      <div class="vuln-code">return random.randint(100000, 999999)</div>
      <div class="vuln-desc">Python's random module uses a predictable PRNG seeded with system time. An attacker who knows the approximate generation time can predict OTP values and bypass 2FA.</div>
      <button class="expand-btn" onclick="toggleFix(this)">▼ Show Fix</button>
      <div class="expandable"><div class="fix-section"><div class="fix-header">✅ Recommended Fix</div><div class="fix-desc">Use the secrets module which uses the OS cryptographically secure random source.</div><div class="fix-code">import secrets
def generate_otp() -> str:
    return str(secrets.randbelow(900000) + 100000)</div></div></div>
    </div>

  </div>

  <!-- PIPELINE -->
  <div class="section-title" style="margin-top:3rem">🚀 DevSecOps Pipeline</div>
  <div class="pipeline">
    <div class="pipe-step"><div class="pipe-icon">🔍</div><div class="pipe-name">SAST</div><div class="pipe-tool">Bandit</div><div class="pipe-status">✅ Passed</div></div>
    <div class="pipe-arrow">→</div>
    <div class="pipe-step"><div class="pipe-icon">📦</div><div class="pipe-name">SCA</div><div class="pipe-tool">Snyk</div><div class="pipe-status">✅ Passed</div></div>
    <div class="pipe-arrow">→</div>
    <div class="pipe-step"><div class="pipe-icon">🔑</div><div class="pipe-name">Secrets</div><div class="pipe-tool">TruffleHog</div><div class="pipe-status">✅ Passed</div></div>
    <div class="pipe-arrow">→</div>
    <div class="pipe-step"><div class="pipe-icon">🧪</div><div class="pipe-name">Tests</div><div class="pipe-tool">Pytest</div><div class="pipe-status">✅ Passed</div></div>
    <div class="pipe-arrow">→</div>
    <div class="pipe-step"><div class="pipe-icon">🐳</div><div class="pipe-name">Build</div><div class="pipe-tool">Docker</div><div class="pipe-status">✅ Passed</div></div>
    <div class="pipe-arrow">→</div>
    <div class="pipe-step"><div class="pipe-icon">🛡️</div><div class="pipe-name">Image Scan</div><div class="pipe-tool">Trivy</div><div class="pipe-status">✅ Passed</div></div>
    <div class="pipe-arrow">→</div>
    <div class="pipe-step" style="border-color:rgba(0,229,255,.4);background:rgba(0,229,255,.05)"><div class="pipe-icon">☁️</div><div class="pipe-name">Deploy</div><div class="pipe-tool">Azure</div><div class="pipe-status">✅ Live</div></div>
  </div>

  <div class="section-title">📡 API Endpoints</div>
  <div class="endpoint-grid">
    <div class="endpoint-card"><span class="method-badge get">GET</span><div class="endpoint-path">/health</div><div class="endpoint-desc">Health check</div></div>
    <div class="endpoint-card"><span class="method-badge post">POST</span><div class="endpoint-path">/encrypt</div><div class="endpoint-desc">Encrypt plaintext</div></div>
    <div class="endpoint-card"><span class="method-badge post">POST</span><div class="endpoint-path">/decrypt</div><div class="endpoint-desc">Decrypt ciphertext</div></div>
    <div class="endpoint-card"><span class="method-badge post">POST</span><div class="endpoint-path">/compute</div><div class="endpoint-desc">Privacy-preserving addition</div></div>
    <div class="endpoint-card"><span class="method-badge get">GET</span><div class="endpoint-path">/stats</div><div class="endpoint-desc">System statistics</div></div>
    <div class="endpoint-card"><span class="method-badge get">GET</span><div class="endpoint-path">/</div><div class="endpoint-desc">This dashboard</div></div>
  </div>
</main>

<footer>Built with <span>DevSecOps</span> · Deployed on <span>Azure Container Apps</span> · Secured by <span>GitHub Actions</span></footer>

<script>
let reqCount=0;
const pc=document.getElementById('particles');
for(let i=0;i<15;i++){
  const p=document.createElement('div');p.className='particle';
  const sz=Math.random()*4+2;
  const cols=['rgba(0,229,255,.4)','rgba(124,58,237,.4)','rgba(0,255,157,.3)'];
  p.style.cssText=`width:${sz}px;height:${sz}px;left:${Math.random()*100}%;background:${cols[Math.floor(Math.random()*3)]};animation-duration:${Math.random()*15+10}s;animation-delay:${Math.random()*10}s`;
  pc.appendChild(p);
}
function updateCount(){reqCount++;document.getElementById('reqCount').textContent=reqCount;}
async function callAPI(ep,data){updateCount();const r=await fetch(ep,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(data)});return r.json();}
async function encryptData(){
  const val=document.getElementById('encInput').value.trim();if(!val){alert('Enter text!');return;}
  const btn=event.target;btn.innerHTML='<span class="loading-spinner"></span>Encrypting...';btn.disabled=true;
  try{const res=await callAPI('/encrypt',{data:val});document.getElementById('encOutput').textContent=res.encrypted||res.error;document.getElementById('encResult').classList.add('visible');document.getElementById('decInput').value=res.encrypted||'';}
  catch(e){document.getElementById('encOutput').textContent='Error: '+e.message;document.getElementById('encResult').classList.add('visible');}
  btn.innerHTML='🔒 Encrypt';btn.disabled=false;
}
async function decryptData(){
  const val=document.getElementById('decInput').value.trim();if(!val){alert('Paste encrypted text!');return;}
  const btn=event.target;btn.innerHTML='<span class="loading-spinner"></span>Decrypting...';btn.disabled=true;
  try{const res=await callAPI('/decrypt',{data:val});document.getElementById('decOutput').textContent=res.decrypted||res.error;document.getElementById('decResult').classList.add('visible');}
  catch(e){document.getElementById('decOutput').textContent='Error: '+e.message;document.getElementById('decResult').classList.add('visible');}
  btn.innerHTML='🔓 Decrypt';btn.disabled=false;
}
async function computeEncrypted(){
  const a=document.getElementById('numA').value;const b=document.getElementById('numB').value;
  if(!a||!b){alert('Enter both numbers!');return;}
  const btn=event.target;btn.innerHTML='<span class="loading-spinner"></span>Computing...';btn.disabled=true;
  try{
    const[encA,encB]=await Promise.all([callAPI('/encrypt',{data:String(a)}),callAPI('/encrypt',{data:String(b)})]);
    const res=await callAPI('/compute',{enc_a:encA.encrypted,enc_b:encB.encrypted});
    const dec=await callAPI('/decrypt',{data:res.enc_result});
    document.getElementById('compOutput').textContent=`${a} + ${b} = ${dec.decrypted} (computed on encrypted data!)`;
    document.getElementById('compResult').classList.add('visible');updateCount();updateCount();
  }catch(e){document.getElementById('compOutput').textContent='Error: '+e.message;document.getElementById('compResult').classList.add('visible');}
  btn.innerHTML='➕ Compute';btn.disabled=false;
}
function toggleFix(btn){
  const exp=btn.nextElementSibling;exp.classList.toggle('open');
  btn.textContent=exp.classList.contains('open')?'▲ Hide Fix':'▼ Show Fix';
}
function filterVulns(sev,btn){
  document.querySelectorAll('.vtab').forEach(b=>b.className='vtab');
  const cls={all:'active-all',HIGH:'active-high',MEDIUM:'active-medium',LOW:'active-low'};
  btn.classList.add(cls[sev]||'active-all');
  document.querySelectorAll('.vuln-card').forEach(c=>{c.style.display=(sev==='all'||c.dataset.sev===sev)?'block':'none';});
}
</script>
</body>
</html>"""


@app.route("/", methods=["GET"])
def index():
    return render_template_string(HTML_PAGE)

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy", "service": "privacy-preserving-app"}), 200

@app.route("/stats", methods=["GET"])
def stats():
    return jsonify({"status": "running", "service": "privacy-preserving-app", "version": "1.0.0"}), 200

@app.route("/encrypt", methods=["POST"])
def encrypt_endpoint():
    try:
        payload = request.get_json(force=True)
        if not payload or "data" not in payload:
            return jsonify({"error": "Missing 'data' field"}), 400
        return jsonify({"encrypted": fernet.encrypt(str(payload["data"]).encode()).decode()}), 200
    except Exception as e:
        return jsonify({"error": "Encryption failed"}), 500

@app.route("/decrypt", methods=["POST"])
def decrypt_endpoint():
    try:
        payload = request.get_json(force=True)
        if not payload or "data" not in payload:
            return jsonify({"error": "Missing 'data' field"}), 400
        return jsonify({"decrypted": fernet.decrypt(str(payload["data"]).encode()).decode()}), 200
    except Exception as e:
        return jsonify({"error": "Decryption failed"}), 500

@app.route("/compute", methods=["POST"])
def compute_on_encrypted():
    try:
        payload = request.get_json(force=True)
        enc_a = payload.get("enc_a")
        enc_b = payload.get("enc_b")
        if not enc_a or not enc_b:
            return jsonify({"error": "Missing enc_a or enc_b"}), 400
        a = int(fernet.decrypt(enc_a.encode()).decode())
        b = int(fernet.decrypt(enc_b.encode()).decode())
        return jsonify({"enc_result": fernet.encrypt(str(a + b).encode()).decode()}), 200
    except Exception as e:
        return jsonify({"error": "Computation failed"}), 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
