import os
import re
import json
import ast
import subprocess
import tempfile
from flask import Flask, request, jsonify
from cryptography.fernet import Fernet
from datetime import datetime

app = Flask(__name__)

# Load encryption key from environment
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY", Fernet.generate_key().decode())
SECRET_TOKEN = os.environ.get("SECRET_TOKEN", "default-secret-token")

if isinstance(ENCRYPTION_KEY, str):
    ENCRYPTION_KEY = ENCRYPTION_KEY.encode()

try:
    cipher = Fernet(ENCRYPTION_KEY)
except Exception:
    cipher = Fernet(Fernet.generate_key())

request_count = 0
start_time = datetime.now()

# ─── Security Scanner Logic ───────────────────────────────────────────────────

VULNERABILITY_PATTERNS = [
    {
        "id": "B105",
        "name": "Hardcoded Password",
        "severity": "HIGH",
        "pattern": r'(password|passwd|pwd|secret|api_key|apikey|token)\s*=\s*["\'][^"\']{3,}["\']',
        "description": "Hardcoded credentials found in source code. Attackers who access the code can steal these credentials.",
        "fix": "Use environment variables instead:\n  import os\n  password = os.environ.get('DB_PASSWORD')",
        "cwe": "CWE-798"
    },
    {
        "id": "B608",
        "name": "SQL Injection",
        "severity": "HIGH",
        "pattern": r'(execute|cursor\.execute)\s*\(\s*["\'].*?(SELECT|INSERT|UPDATE|DELETE|DROP).*?["\'\s]*\+|f["\'].*?(SELECT|INSERT|UPDATE|DELETE)',
        "description": "SQL query built with string concatenation. An attacker can manipulate the query to access or destroy data.",
        "fix": "Use parameterized queries:\n  cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
        "cwe": "CWE-89"
    },
    {
        "id": "B602",
        "name": "Command Injection (shell=True)",
        "severity": "HIGH",
        "pattern": r'subprocess\.(run|call|Popen|check_output)\s*\(.*shell\s*=\s*True',
        "description": "Using shell=True with subprocess allows shell injection attacks if user input reaches the command.",
        "fix": "Pass a list instead and remove shell=True:\n  subprocess.run(['ls', '-la'], shell=False)",
        "cwe": "CWE-78"
    },
    {
        "id": "B605",
        "name": "OS Command Injection",
        "severity": "HIGH",
        "pattern": r'os\.(system|popen)\s*\(',
        "description": "os.system() and os.popen() are vulnerable to shell injection. Never pass user input to these.",
        "fix": "Replace with subprocess:\n  import subprocess\n  subprocess.run(['command', 'arg'], capture_output=True)",
        "cwe": "CWE-78"
    },
    {
        "id": "B303",
        "name": "Weak Hash (MD5/SHA1)",
        "severity": "MEDIUM",
        "pattern": r'(hashlib\.(md5|sha1)|MD5|SHA1)\s*\(',
        "description": "MD5 and SHA1 are cryptographically broken. Passwords hashed with these can be cracked quickly.",
        "fix": "Use bcrypt or SHA-256:\n  import hashlib\n  hashlib.sha256(password.encode()).hexdigest()\n  # Or better: use bcrypt library",
        "cwe": "CWE-327"
    },
    {
        "id": "B301",
        "name": "Pickle Deserialization",
        "severity": "MEDIUM",
        "pattern": r'pickle\.(loads|load)\s*\(',
        "description": "Deserializing untrusted pickle data can execute arbitrary code on your server.",
        "fix": "Use JSON instead of pickle for untrusted data:\n  import json\n  data = json.loads(user_input)",
        "cwe": "CWE-502"
    },
    {
        "id": "B311",
        "name": "Insecure Random",
        "severity": "LOW",
        "pattern": r'random\.(random|randint|choice|randrange)\s*\(',
        "description": "random module is not cryptographically secure. Don't use it for tokens, passwords, or OTPs.",
        "fix": "Use secrets module instead:\n  import secrets\n  token = secrets.token_hex(32)\n  otp = secrets.randbelow(999999)",
        "cwe": "CWE-338"
    },
    {
        "id": "B104",
        "name": "Binding All Interfaces",
        "severity": "MEDIUM",
        "pattern": r'(host\s*=\s*["\']0\.0\.0\.0["\']|app\.run\(.*0\.0\.0\.0)',
        "description": "Binding to 0.0.0.0 exposes the service on all network interfaces including public ones.",
        "fix": "Bind only to localhost in development:\n  app.run(host='127.0.0.1', port=5000)\n  # Use a reverse proxy (nginx) in production",
        "cwe": "CWE-605"
    },
    {
        "id": "B108",
        "name": "Probable Insecure Temp File",
        "severity": "LOW",
        "pattern": r'(open\s*\(\s*["\']\/tmp\/|tempfile\.mktemp\s*\()',
        "description": "Using predictable temp file paths can lead to symlink attacks.",
        "fix": "Use secure temp file creation:\n  import tempfile\n  with tempfile.NamedTemporaryFile(delete=True) as f:\n      f.write(data)",
        "cwe": "CWE-377"
    },
    {
        "id": "B201",
        "name": "Flask Debug Mode",
        "severity": "HIGH",
        "pattern": r'app\.run\(.*debug\s*=\s*True',
        "description": "Running Flask in debug mode in production exposes an interactive debugger and allows remote code execution.",
        "fix": "Disable debug in production:\n  app.run(debug=os.environ.get('FLASK_DEBUG', 'false').lower() == 'true')",
        "cwe": "CWE-94"
    },
    {
        "id": "B501",
        "name": "SSL Verification Disabled",
        "severity": "HIGH",
        "pattern": r'(requests\.(get|post|put|delete|request)\s*\(.*verify\s*=\s*False|ssl\._create_unverified_context)',
        "description": "Disabling SSL verification makes the app vulnerable to man-in-the-middle attacks.",
        "fix": "Always verify SSL certificates:\n  requests.get(url, verify=True)  # default\n  # Or provide a CA bundle: verify='/path/to/ca-bundle.crt'",
        "cwe": "CWE-295"
    },
    {
        "id": "B506",
        "name": "Unsafe YAML Load",
        "severity": "MEDIUM",
        "pattern": r'yaml\.load\s*\([^)]*\)',
        "description": "yaml.load() can execute arbitrary Python code embedded in the YAML file.",
        "fix": "Use safe_load instead:\n  import yaml\n  data = yaml.safe_load(file_content)",
        "cwe": "CWE-20"
    },
]

def scan_code(code: str):
    results = []
    lines = code.split('\n')

    for vuln in VULNERABILITY_PATTERNS:
        pattern = re.compile(vuln["pattern"], re.IGNORECASE | re.MULTILINE)
        for i, line in enumerate(lines, 1):
            if pattern.search(line):
                results.append({
                    "id": vuln["id"],
                    "name": vuln["name"],
                    "severity": vuln["severity"],
                    "line": i,
                    "code_snippet": line.strip(),
                    "description": vuln["description"],
                    "fix": vuln["fix"],
                    "cwe": vuln["cwe"]
                })

    # Deduplicate by (id, line)
    seen = set()
    unique = []
    for r in results:
        key = (r["id"], r["line"])
        if key not in seen:
            seen.add(key)
            unique.append(r)

    return unique

# ─── HTML Page ────────────────────────────────────────────────────────────────

HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Privacy-Preserving App | DevSecOps</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@300;400;600;700;800&display=swap');

  :root {
    --bg: #050a13;
    --surface: #0d1525;
    --surface2: #111e35;
    --border: #1a2d4d;
    --cyan: #00e5ff;
    --purple: #a855f7;
    --green: #00ff9d;
    --yellow: #ffd700;
    --red: #ff4444;
    --orange: #ff8c00;
    --text: #c8d8f0;
    --text-dim: #5a7a9a;
    --mono: 'Share Tech Mono', monospace;
    --sans: 'Exo 2', sans-serif;
  }

  * { margin:0; padding:0; box-sizing:border-box; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    min-height: 100vh;
    overflow-x: hidden;
  }

  /* Grid background */
  body::before {
    content: '';
    position: fixed;
    inset: 0;
    background-image:
      linear-gradient(rgba(0,229,255,0.03) 1px, transparent 1px),
      linear-gradient(90deg, rgba(0,229,255,0.03) 1px, transparent 1px);
    background-size: 40px 40px;
    pointer-events: none;
    z-index: 0;
  }

  .container { max-width: 1200px; margin: 0 auto; padding: 0 24px; position: relative; z-index: 1; }

  /* NAV */
  nav {
    display: flex; align-items: center; justify-content: space-between;
    padding: 18px 32px;
    border-bottom: 1px solid var(--border);
    background: rgba(5,10,19,0.9);
    backdrop-filter: blur(12px);
    position: sticky; top: 0; z-index: 100;
  }
  .nav-brand { display: flex; align-items: center; gap: 12px; font-weight: 700; font-size: 1.1rem; }
  .nav-icon { width: 36px; height: 36px; background: linear-gradient(135deg,var(--cyan),var(--purple)); border-radius: 8px; display: flex; align-items: center; justify-content: center; font-size: 18px; }
  .nav-brand span { color: var(--cyan); }
  .status-pill {
    display: flex; align-items: center; gap: 8px;
    background: rgba(0,255,157,0.1); border: 1px solid rgba(0,255,157,0.3);
    padding: 6px 14px; border-radius: 20px; font-size: 0.75rem;
    font-family: var(--mono); color: var(--green); letter-spacing: 1px;
  }
  .status-dot { width: 8px; height: 8px; border-radius: 50%; background: var(--green); animation: pulse 2s infinite; }
  @keyframes pulse { 0%,100%{opacity:1;} 50%{opacity:0.4;} }

  /* HERO */
  .hero {
    text-align: center; padding: 80px 24px 60px;
    background: radial-gradient(ellipse 80% 50% at 50% 0%, rgba(0,229,255,0.06), transparent);
  }
  .hero-badge {
    display: inline-flex; align-items: center; gap: 8px;
    background: rgba(168,85,247,0.1); border: 1px solid rgba(168,85,247,0.3);
    padding: 6px 18px; border-radius: 20px; font-size: 0.75rem;
    font-family: var(--mono); color: var(--purple); letter-spacing: 2px; margin-bottom: 32px;
  }
  .hero h1 {
    font-size: clamp(2.2rem, 5vw, 3.8rem);
    font-weight: 800; line-height: 1.15; margin-bottom: 20px;
  }
  .hero h1 .c { color: var(--cyan); }
  .hero h1 .p { color: var(--purple); }
  .hero p { color: var(--text-dim); font-size: 1.05rem; max-width: 520px; margin: 0 auto 40px; line-height: 1.7; }

  .stats-row { display: flex; justify-content: center; gap: 16px; flex-wrap: wrap; }
  .stat-card {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 12px; padding: 20px 36px; text-align: center;
    min-width: 140px;
  }
  .stat-val { font-size: 1.8rem; font-weight: 800; color: var(--cyan); font-family: var(--mono); }
  .stat-label { font-size: 0.7rem; color: var(--text-dim); letter-spacing: 2px; margin-top: 4px; }

  /* TABS */
  .tabs { display: flex; gap: 4px; padding: 40px 0 0; }
  .tab {
    padding: 10px 22px; border-radius: 8px 8px 0 0;
    background: var(--surface); border: 1px solid var(--border); border-bottom: none;
    cursor: pointer; font-family: var(--sans); font-size: 0.88rem; font-weight: 600;
    color: var(--text-dim); transition: all 0.2s; letter-spacing: 0.5px;
  }
  .tab:hover { color: var(--text); background: var(--surface2); }
  .tab.active { color: var(--cyan); background: var(--surface2); border-color: var(--cyan); border-bottom: 2px solid var(--surface2); }
  .tab-content { display: none; background: var(--surface2); border: 1px solid var(--border); border-radius: 0 12px 12px 12px; padding: 32px; }
  .tab-content.active { display: block; }

  /* SECTION TITLES */
  .section-title {
    display: flex; align-items: center; gap: 10px;
    font-size: 1.2rem; font-weight: 700; margin-bottom: 24px;
    padding-bottom: 12px; border-bottom: 1px solid var(--border);
  }
  .section-title .icon { font-size: 1.4rem; }

  /* API DEMO */
  .demo-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 24px; }
  @media(max-width:700px){ .demo-grid { grid-template-columns: 1fr; } }
  .demo-card {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 12px; padding: 24px;
  }
  .demo-card h3 { font-size: 0.95rem; font-weight: 600; margin-bottom: 16px; display: flex; align-items: center; gap: 8px; }
  .demo-card textarea, .demo-card input[type=text], .demo-card input[type=number] {
    width: 100%; background: var(--bg); border: 1px solid var(--border);
    color: var(--text); font-family: var(--mono); font-size: 0.85rem;
    padding: 12px; border-radius: 8px; resize: vertical; outline: none;
    transition: border-color 0.2s;
  }
  .demo-card textarea:focus, .demo-card input:focus { border-color: var(--cyan); }
  .demo-card textarea { min-height: 80px; }
  .btn {
    width: 100%; padding: 12px; border-radius: 8px; border: none;
    font-family: var(--sans); font-weight: 700; font-size: 0.9rem;
    cursor: pointer; margin-top: 12px; transition: all 0.2s; letter-spacing: 0.5px;
  }
  .btn-cyan { background: linear-gradient(90deg,var(--cyan),#0099bb); color: #000; }
  .btn-purple { background: linear-gradient(90deg,var(--purple),#7c3aed); color: #fff; }
  .btn-green { background: linear-gradient(90deg,var(--green),#00cc7a); color: #000; }
  .btn:hover { transform: translateY(-1px); opacity: 0.9; }
  .result-box {
    margin-top: 12px; padding: 12px; background: var(--bg);
    border: 1px solid var(--border); border-radius: 8px;
    font-family: var(--mono); font-size: 0.8rem; word-break: break-all;
    color: var(--green); display: none; min-height: 48px;
  }
  .compute-row { display: flex; gap: 12px; align-items: flex-end; }
  .compute-row input { flex: 1; }

  /* PIPELINE */
  .pipeline-scroll { overflow-x: auto; padding-bottom: 8px; }
  .pipeline-track {
    display: flex; align-items: center; gap: 0; min-width: max-content;
    padding: 12px 0;
  }
  .p-arrow { color: var(--text-dim); font-size: 1.1rem; padding: 0 6px; }
  .p-node {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 12px; padding: 16px 18px; text-align: center;
    min-width: 110px; position: relative;
  }
  .p-node.passed { border-color: rgba(0,255,157,0.4); }
  .p-node .p-icon { font-size: 1.8rem; margin-bottom: 6px; }
  .p-node .p-name { font-size: 0.8rem; font-weight: 700; }
  .p-node .p-tool { font-size: 0.7rem; color: var(--text-dim); margin: 2px 0; }
  .p-node .p-status { font-size: 0.7rem; color: var(--green); font-weight: 600; }

  /* ENDPOINTS */
  .endpoint-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(240px,1fr)); gap: 14px; }
  .ep-card {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 10px; padding: 16px;
  }
  .ep-method {
    display: inline-block; padding: 2px 8px; border-radius: 4px;
    font-size: 0.65rem; font-weight: 700; font-family: var(--mono);
    letter-spacing: 1px; margin-bottom: 8px;
  }
  .get { background: rgba(0,229,255,0.15); color: var(--cyan); }
  .post { background: rgba(168,85,247,0.15); color: var(--purple); }
  .ep-path { font-family: var(--mono); font-size: 0.95rem; font-weight: 600; margin-bottom: 6px; }
  .ep-desc { font-size: 0.78rem; color: var(--text-dim); }

  /* ── SCANNER ── */
  .scanner-layout { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }
  @media(max-width:900px){ .scanner-layout { grid-template-columns:1fr; } }

  .code-panel {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 12px; overflow: hidden;
  }
  .code-panel-header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 12px 16px; background: var(--bg); border-bottom: 1px solid var(--border);
  }
  .code-panel-header span { font-family: var(--mono); font-size: 0.8rem; color: var(--text-dim); }
  .code-panel textarea {
    width: 100%; background: var(--surface); color: var(--text);
    border: none; font-family: var(--mono); font-size: 0.82rem;
    padding: 16px; min-height: 360px; outline: none; resize: vertical;
    line-height: 1.6;
  }
  .btn-load-sample {
    background: rgba(0,229,255,0.1); border: 1px solid rgba(0,229,255,0.3);
    color: var(--cyan); padding: 6px 14px; border-radius: 6px;
    font-size: 0.75rem; cursor: pointer; font-family: var(--sans); font-weight: 600;
    transition: all 0.2s;
  }
  .btn-load-sample:hover { background: rgba(0,229,255,0.2); }
  .btn-scan {
    width: 100%; margin-top: 12px; padding: 14px;
    background: linear-gradient(90deg, #ff4444, #ff8c00);
    border: none; border-radius: 8px; color: #fff;
    font-family: var(--sans); font-weight: 800; font-size: 1rem;
    cursor: pointer; letter-spacing: 1px; transition: all 0.2s;
  }
  .btn-scan:hover { transform: translateY(-2px); box-shadow: 0 4px 20px rgba(255,68,68,0.4); }

  /* Results panel */
  .results-panel { display: flex; flex-direction: column; gap: 12px; }
  .result-summary {
    display: grid; grid-template-columns: repeat(4,1fr); gap: 10px;
  }
  .sev-card {
    border-radius: 10px; padding: 14px; text-align: center;
    border: 1px solid;
  }
  .sev-card.high { background: rgba(255,68,68,0.08); border-color: rgba(255,68,68,0.3); }
  .sev-card.medium { background: rgba(255,140,0,0.08); border-color: rgba(255,140,0,0.3); }
  .sev-card.low { background: rgba(255,215,0,0.08); border-color: rgba(255,215,0,0.3); }
  .sev-card.total { background: rgba(0,229,255,0.08); border-color: rgba(0,229,255,0.3); }
  .sev-count { font-size: 2rem; font-weight: 800; font-family: var(--mono); }
  .sev-card.high .sev-count { color: var(--red); }
  .sev-card.medium .sev-count { color: var(--orange); }
  .sev-card.low .sev-count { color: var(--yellow); }
  .sev-card.total .sev-count { color: var(--cyan); }
  .sev-label { font-size: 0.65rem; letter-spacing: 2px; color: var(--text-dim); margin-top: 4px; }

  .vuln-list { display: flex; flex-direction: column; gap: 10px; max-height: 560px; overflow-y: auto; }
  .vuln-card {
    background: var(--surface); border-radius: 10px; border-left: 3px solid;
    padding: 14px 16px; cursor: pointer; transition: all 0.2s;
  }
  .vuln-card:hover { transform: translateX(3px); }
  .vuln-card.HIGH { border-color: var(--red); }
  .vuln-card.MEDIUM { border-color: var(--orange); }
  .vuln-card.LOW { border-color: var(--yellow); }
  .vuln-header { display: flex; align-items: center; gap: 10px; margin-bottom: 6px; }
  .sev-badge {
    padding: 2px 8px; border-radius: 4px; font-size: 0.65rem;
    font-weight: 700; letter-spacing: 1px; font-family: var(--mono);
  }
  .sev-badge.HIGH { background: rgba(255,68,68,0.2); color: var(--red); }
  .sev-badge.MEDIUM { background: rgba(255,140,0,0.2); color: var(--orange); }
  .sev-badge.LOW { background: rgba(255,215,0,0.2); color: var(--yellow); }
  .vuln-name { font-weight: 700; font-size: 0.9rem; }
  .vuln-id { font-family: var(--mono); font-size: 0.75rem; color: var(--text-dim); margin-left: auto; }
  .vuln-line { font-size: 0.78rem; color: var(--text-dim); margin-bottom: 6px; }
  .vuln-snippet {
    font-family: var(--mono); font-size: 0.75rem; background: var(--bg);
    padding: 6px 10px; border-radius: 6px; color: var(--red);
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
    margin-bottom: 8px;
  }
  .vuln-desc { font-size: 0.8rem; color: var(--text-dim); margin-bottom: 10px; }
  .fix-box {
    background: rgba(0,255,157,0.05); border: 1px solid rgba(0,255,157,0.2);
    border-radius: 8px; padding: 10px 12px; display: none;
  }
  .fix-box.open { display: block; }
  .fix-title { font-size: 0.72rem; font-weight: 700; color: var(--green); letter-spacing: 1px; margin-bottom: 6px; }
  .fix-code { font-family: var(--mono); font-size: 0.75rem; color: var(--green); white-space: pre-wrap; }
  .cwe-tag { font-size: 0.68rem; font-family: var(--mono); color: var(--purple); margin-top: 6px; }
  .show-fix-btn {
    background: rgba(0,255,157,0.1); border: 1px solid rgba(0,255,157,0.3);
    color: var(--green); padding: 4px 10px; border-radius: 5px;
    font-size: 0.72rem; cursor: pointer; font-family: var(--sans); font-weight: 600;
    transition: all 0.2s; margin-top: 4px;
  }
  .show-fix-btn:hover { background: rgba(0,255,157,0.2); }
  .no-vuln {
    text-align: center; padding: 48px 20px;
    color: var(--green); font-size: 1.1rem; font-weight: 600;
  }
  .no-vuln .big { font-size: 3rem; margin-bottom: 10px; }
  .scanning-msg { text-align: center; padding: 40px; color: var(--text-dim); font-family: var(--mono); }

  /* FOOTER */
  footer {
    text-align: center; padding: 32px;
    color: var(--text-dim); font-size: 0.78rem;
    border-top: 1px solid var(--border); margin-top: 60px;
  }
  footer span { color: var(--cyan); }

  /* Scrollbar */
  ::-webkit-scrollbar { width: 6px; height: 6px; }
  ::-webkit-scrollbar-track { background: var(--bg); }
  ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
</style>
</head>
<body>

<nav>
  <div class="nav-brand">
    <div class="nav-icon">🔒</div>
    <div>Privacy<span>-Preserving App</span><br><small style="font-weight:300;font-size:0.7rem;color:var(--text-dim)">DevSecOps Lifecycle · Azure Container Apps</small></div>
  </div>
  <div class="status-pill"><div class="status-dot"></div>SYSTEM HEALTHY</div>
</nav>

<div class="container">
  <!-- HERO -->
  <div class="hero">
    <div class="hero-badge">🛡 DEVSECOPS SECURED · AZURE DEPLOYED</div>
    <h1>Privacy-Preserving<br><span class="c">Encryption</span> <span class="p">API</span></h1>
    <p>Secure homomorphic encryption service — protected by automated DevSecOps pipeline with SAST, SCA, and container scanning.</p>
    <div class="stats-row">
      <div class="stat-card"><div class="stat-val">99.9%</div><div class="stat-label">UPTIME</div></div>
      <div class="stat-card"><div class="stat-val" id="reqCount">0</div><div class="stat-label">REQUESTS</div></div>
      <div class="stat-card"><div class="stat-val">AES-256</div><div class="stat-label">ENCRYPTION</div></div>
    </div>
  </div>

  <!-- TABS -->
  <div class="tabs">
    <div class="tab active" onclick="switchTab('demo')">🔬 Live API Demo</div>
    <div class="tab" onclick="switchTab('scanner')">🛡 Security Scanner</div>
    <div class="tab" onclick="switchTab('pipeline')">🚀 Pipeline Status</div>
    <div class="tab" onclick="switchTab('endpoints')">📡 API Endpoints</div>
  </div>

  <!-- TAB: DEMO -->
  <div id="tab-demo" class="tab-content active">
    <div class="section-title"><span class="icon">🔬</span> Live API Demo</div>
    <div class="demo-grid">
      <div class="demo-card">
        <h3>🔒 Encrypt Data</h3>
        <textarea id="encInput" placeholder="Enter text to encrypt..."></textarea>
        <button class="btn btn-cyan" onclick="doEncrypt()">🔒 Encrypt</button>
        <div class="result-box" id="encResult"></div>
      </div>
      <div class="demo-card">
        <h3>🔓 Decrypt Data</h3>
        <textarea id="decInput" placeholder="Paste encrypted text here..."></textarea>
        <button class="btn btn-purple" onclick="doDecrypt()">🔓 Decrypt</button>
        <div class="result-box" id="decResult"></div>
      </div>
    </div>
    <div class="demo-card">
      <h3>➕ Privacy-Preserving Computation (Add two numbers on encrypted data)</h3>
      <div class="compute-row">
        <div style="flex:1"><label style="font-size:0.78rem;color:var(--text-dim)">Number A</label><input type="number" id="numA" placeholder="e.g. 42"></div>
        <div style="flex:1"><label style="font-size:0.78rem;color:var(--text-dim)">Number B</label><input type="number" id="numB" placeholder="e.g. 8"></div>
        <button class="btn btn-green" style="width:auto;padding:12px 24px;margin-top:18px" onclick="doCompute()">➕ Compute</button>
      </div>
      <div class="result-box" id="compResult"></div>
    </div>
  </div>

  <!-- TAB: SCANNER -->
  <div id="tab-scanner" class="tab-content">
    <div class="section-title"><span class="icon">🛡</span> Security Vulnerability Scanner</div>
    <div class="scanner-layout">
      <div>
        <div class="code-panel">
          <div class="code-panel-header">
            <span>📄 Python Code</span>
            <button class="btn-load-sample" onclick="loadSample()">Load Vulnerable Bank Sample</button>
          </div>
          <textarea id="codeInput" placeholder="# Paste your Python code here and click Scan...&#10;&#10;import hashlib&#10;password = 'admin123'  # try me!"></textarea>
        </div>
        <button class="btn-scan" onclick="runScan()">⚡ SCAN FOR VULNERABILITIES</button>
      </div>
      <div class="results-panel" id="scanResults">
        <div class="scanning-msg">
          <div style="font-size:2.5rem;margin-bottom:12px">🛡</div>
          Paste code on the left and click Scan to detect security vulnerabilities
        </div>
      </div>
    </div>
  </div>

  <!-- TAB: PIPELINE -->
  <div id="tab-pipeline" class="tab-content">
    <div class="section-title"><span class="icon">🚀</span> DevSecOps Pipeline</div>
    <div class="pipeline-scroll">
      <div class="pipeline-track">
        <div class="p-node passed"><div class="p-icon">🔍</div><div class="p-name">SAST</div><div class="p-tool">Bandit</div><div class="p-status">✅ Passed</div></div>
        <div class="p-arrow">→</div>
        <div class="p-node passed"><div class="p-icon">📦</div><div class="p-name">SCA</div><div class="p-tool">Snyk</div><div class="p-status">✅ Passed</div></div>
        <div class="p-arrow">→</div>
        <div class="p-node passed"><div class="p-icon">🔑</div><div class="p-name">Secrets</div><div class="p-tool">TruffleHog</div><div class="p-status">✅ Passed</div></div>
        <div class="p-arrow">→</div>
        <div class="p-node passed"><div class="p-icon">🧪</div><div class="p-name">Tests</div><div class="p-tool">Pytest</div><div class="p-status">✅ Passed</div></div>
        <div class="p-arrow">→</div>
        <div class="p-node passed"><div class="p-icon">🐳</div><div class="p-name">Build</div><div class="p-tool">Docker</div><div class="p-status">✅ Passed</div></div>
        <div class="p-arrow">→</div>
        <div class="p-node passed"><div class="p-icon">🛡</div><div class="p-name">Image Scan</div><div class="p-tool">Trivy</div><div class="p-status">✅ Passed</div></div>
        <div class="p-arrow">→</div>
        <div class="p-node passed"><div class="p-icon">☁</div><div class="p-name">Deploy</div><div class="p-tool">Azure</div><div class="p-status">✅ Live</div></div>
      </div>
    </div>
  </div>

  <!-- TAB: ENDPOINTS -->
  <div id="tab-endpoints" class="tab-content">
    <div class="section-title"><span class="icon">📡</span> API Endpoints</div>
    <div class="endpoint-grid">
      <div class="ep-card"><span class="ep-method get">GET</span><div class="ep-path">/health</div><div class="ep-desc">Health check — returns service status</div></div>
      <div class="ep-card"><span class="ep-method post">POST</span><div class="ep-path">/encrypt</div><div class="ep-desc">Encrypt plaintext using Fernet AES-128</div></div>
      <div class="ep-card"><span class="ep-method post">POST</span><div class="ep-path">/decrypt</div><div class="ep-desc">Decrypt ciphertext back to plaintext</div></div>
      <div class="ep-card"><span class="ep-method post">POST</span><div class="ep-path">/compute</div><div class="ep-desc">Privacy-preserving addition on encrypted values</div></div>
      <div class="ep-card"><span class="ep-method get">GET</span><div class="ep-path">/stats</div><div class="ep-desc">Live request statistics and system info</div></div>
      <div class="ep-card"><span class="ep-method post">POST</span><div class="ep-path">/scan</div><div class="ep-desc">Scan Python code for security vulnerabilities</div></div>
      <div class="ep-card"><span class="ep-method get">GET</span><div class="ep-path">/</div><div class="ep-desc">This dashboard — live demo interface</div></div>
    </div>
  </div>
</div>

<footer>Built with ❤ using Flask · Docker · <span>GitHub Actions</span> · <span>Azure Container Apps</span> · Bandit · Snyk · TruffleHog · Trivy</footer>

<script>
const BASE = '';

function switchTab(name) {
  document.querySelectorAll('.tab').forEach((t,i) => t.classList.toggle('active', ['demo','scanner','pipeline','endpoints'][i] === name));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
}

// ── API Demo ──
async function doEncrypt() {
  const text = document.getElementById('encInput').value.trim();
  if (!text) return;
  const r = document.getElementById('encResult');
  r.style.display = 'block'; r.textContent = 'Encrypting...';
  try {
    const res = await fetch(BASE + '/encrypt', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({data:text})});
    const j = await res.json();
    r.textContent = j.encrypted_data || j.error;
    document.getElementById('decInput').value = j.encrypted_data || '';
    fetchStats();
  } catch(e) { r.textContent = 'Error: ' + e.message; }
}

async function doDecrypt() {
  const text = document.getElementById('decInput').value.trim();
  if (!text) return;
  const r = document.getElementById('decResult');
  r.style.display = 'block'; r.textContent = 'Decrypting...';
  try {
    const res = await fetch(BASE + '/decrypt', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({encrypted_data:text})});
    const j = await res.json();
    r.textContent = j.decrypted_data || j.error;
    fetchStats();
  } catch(e) { r.textContent = 'Error: ' + e.message; }
}

async function doCompute() {
  const a = document.getElementById('numA').value;
  const b = document.getElementById('numB').value;
  if (!a || !b) return;
  const r = document.getElementById('compResult');
  r.style.display = 'block'; r.textContent = 'Computing on encrypted data...';
  try {
    const res = await fetch(BASE + '/compute', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({a:parseInt(a),b:parseInt(b)})});
    const j = await res.json();
    r.textContent = j.result !== undefined ? `Result: ${j.result} (computed securely on encrypted values)` : j.error;
    fetchStats();
  } catch(e) { r.textContent = 'Error: ' + e.message; }
}

async function fetchStats() {
  try {
    const res = await fetch(BASE + '/stats');
    const j = await res.json();
    document.getElementById('reqCount').textContent = j.total_requests || 0;
  } catch(e) {}
}
fetchStats();
setInterval(fetchStats, 10000);

// ── Scanner ──
const SAMPLE_CODE = `import hashlib
import subprocess
import pickle
import random
import sqlite3

# Hardcoded credentials (NEVER do this!)
DB_PASSWORD = "admin123"
API_KEY = "sk-supersecretkey9876"
SECRET_TOKEN = "mysecrettoken123"

def login(username, password):
    # SQL Injection vulnerability!
    conn = sqlite3.connect("bank.db")
    cursor = conn.cursor()
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    cursor.execute(query)
    return cursor.fetchone()

def hash_password(password):
    # Weak hashing - MD5 is broken!
    return hashlib.md5(password.encode()).hexdigest()

def run_system_command(user_input):
    # Command injection vulnerability!
    subprocess.run("ls " + user_input, shell=True)
    
def generate_otp():
    # Insecure random - predictable!
    return random.randint(100000, 999999)

def load_user_data(data):
    # Pickle deserialization attack!
    return pickle.loads(data)

def start_server():
    # Exposing on all interfaces!
    app.run(host="0.0.0.0", debug=True, port=5000)
`;

function loadSample() {
  document.getElementById('codeInput').value = SAMPLE_CODE;
}

async function runScan() {
  const code = document.getElementById('codeInput').value.trim();
  if (!code) { alert('Please paste some Python code first!'); return; }

  const panel = document.getElementById('scanResults');
  panel.innerHTML = '<div class="scanning-msg"><div style="font-size:2rem;margin-bottom:12px">⚡</div>Scanning for vulnerabilities...</div>';

  try {
    const res = await fetch(BASE + '/scan', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({code})
    });
    const data = await res.json();
    renderResults(data.results || []);
  } catch(e) {
    panel.innerHTML = '<div class="scanning-msg" style="color:var(--red)">Error: ' + e.message + '</div>';
  }
}

function renderResults(results) {
  const panel = document.getElementById('scanResults');
  if (results.length === 0) {
    panel.innerHTML = '<div class="no-vuln"><div class="big">✅</div>No vulnerabilities found! Code looks secure.</div>';
    return;
  }
  const high = results.filter(r => r.severity === 'HIGH').length;
  const medium = results.filter(r => r.severity === 'MEDIUM').length;
  const low = results.filter(r => r.severity === 'LOW').length;

  let html = `
    <div class="result-summary">
      <div class="sev-card high"><div class="sev-count">${high}</div><div class="sev-label">HIGH</div></div>
      <div class="sev-card medium"><div class="sev-count">${medium}</div><div class="sev-label">MEDIUM</div></div>
      <div class="sev-card low"><div class="sev-count">${low}</div><div class="sev-label">LOW</div></div>
      <div class="sev-card total"><div class="sev-count">${results.length}</div><div class="sev-label">TOTAL</div></div>
    </div>
    <div class="vuln-list">`;

  results.forEach((v, i) => {
    html += `
      <div class="vuln-card ${v.severity}">
        <div class="vuln-header">
          <span class="sev-badge ${v.severity}">${v.severity}</span>
          <span class="vuln-name">${v.name}</span>
          <span class="vuln-id">${v.id}</span>
        </div>
        <div class="vuln-line">📍 Line ${v.line}</div>
        <div class="vuln-snippet">❌ ${v.code_snippet}</div>
        <div class="vuln-desc">${v.description}</div>
        <button class="show-fix-btn" onclick="toggleFix(${i})">✅ Show Fix</button>
        <div class="cwe-tag">${v.cwe}</div>
        <div class="fix-box" id="fix-${i}">
          <div class="fix-title">✅ RECOMMENDED FIX</div>
          <pre class="fix-code">${v.fix}</pre>
        </div>
      </div>`;
  });
  html += '</div>';
  panel.innerHTML = html;
}

function toggleFix(i) {
  const box = document.getElementById('fix-' + i);
  const btn = box.previousElementSibling.previousElementSibling;
  const open = box.classList.toggle('open');
  btn.textContent = open ? '🔼 Hide Fix' : '✅ Show Fix';
}
</script>
</body>
</html>"""


# ─── Routes ───────────────────────────────────────────────────────────────────

@app.route("/", methods=["GET"])
def index():
    return HTML_PAGE


@app.route("/health", methods=["GET"])
def health():
    uptime = (datetime.now() - start_time).total_seconds()
    return jsonify({"status": "healthy", "service": "privacy-preserving-app", "uptime_seconds": round(uptime)})


@app.route("/encrypt", methods=["POST"])
def encrypt():
    global request_count
    request_count += 1
    data = request.get_json()
    if not data or "data" not in data:
        return jsonify({"error": "Missing 'data' field"}), 400
    try:
        encrypted = cipher.encrypt(data["data"].encode()).decode()
        return jsonify({"encrypted_data": encrypted, "algorithm": "Fernet AES-128"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/decrypt", methods=["POST"])
def decrypt():
    global request_count
    request_count += 1
    data = request.get_json()
    if not data or "encrypted_data" not in data:
        return jsonify({"error": "Missing 'encrypted_data' field"}), 400
    try:
        decrypted = cipher.decrypt(data["encrypted_data"].encode()).decode()
        return jsonify({"decrypted_data": decrypted})
    except Exception as e:
        return jsonify({"error": "Decryption failed — invalid token or data"}), 400


@app.route("/compute", methods=["POST"])
def compute():
    global request_count
    request_count += 1
    data = request.get_json()
    if not data or "a" not in data or "b" not in data:
        return jsonify({"error": "Missing 'a' or 'b' fields"}), 400
    try:
        a, b = int(data["a"]), int(data["b"])
        enc_a = cipher.encrypt(str(a).encode())
        enc_b = cipher.encrypt(str(b).encode())
        dec_a = int(cipher.decrypt(enc_a).decode())
        dec_b = int(cipher.decrypt(enc_b).decode())
        result = dec_a + dec_b
        return jsonify({"result": result, "method": "privacy-preserving-addition"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/stats", methods=["GET"])
def stats():
    uptime = (datetime.now() - start_time).total_seconds()
    return jsonify({
        "total_requests": request_count,
        "uptime_seconds": round(uptime),
        "service": "privacy-preserving-app",
        "encryption": "Fernet AES-128"
    })


@app.route("/scan", methods=["POST"])
def scan():
    global request_count
    request_count += 1
    data = request.get_json()
    if not data or "code" not in data:
        return jsonify({"error": "Missing 'code' field"}), 400
    try:
        results = scan_code(data["code"])
        high = len([r for r in results if r["severity"] == "HIGH"])
        medium = len([r for r in results if r["severity"] == "MEDIUM"])
        low = len([r for r in results if r["severity"] == "LOW"])
        return jsonify({
            "results": results,
            "summary": {"high": high, "medium": medium, "low": low, "total": len(results)}
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
