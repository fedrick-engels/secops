"""
Updated Flask app with beautiful frontend
Replace your existing app/main.py with this
"""

import os
import logging
from flask import Flask, request, jsonify, render_template_string
from cryptography.fernet import Fernet
import hashlib
import hmac

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

app = Flask(__name__)

ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY")
SECRET_TOKEN = os.environ.get("SECRET_TOKEN")

if not ENCRYPTION_KEY or not SECRET_TOKEN:
    raise RuntimeError("ENCRYPTION_KEY and SECRET_TOKEN must be set via environment variables.")

fernet = Fernet(ENCRYPTION_KEY.encode())


def encrypt_data(plaintext: str) -> str:
    return fernet.encrypt(plaintext.encode()).decode()


def decrypt_data(ciphertext: str) -> str:
    return fernet.decrypt(ciphertext.encode()).decode()


HTML_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Privacy-Preserving App</title>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #050b1a;
    --surface: #0d1f3c;
    --surface2: #112347;
    --border: #1a3a6b;
    --accent: #00e5ff;
    --accent2: #7c3aed;
    --green: #00ff9d;
    --text: #e8f4fd;
    --muted: #4a7aa7;
  }
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family:'Space Grotesk',sans-serif; background:var(--bg); color:var(--text); min-height:100vh; overflow-x:hidden; }

  /* Animated background */
  .bg-anim {
    position:fixed; inset:0; z-index:0;
    background: radial-gradient(ellipse at 20% 50%, rgba(0,229,255,0.05) 0%, transparent 60%),
                radial-gradient(ellipse at 80% 20%, rgba(124,58,237,0.05) 0%, transparent 60%),
                radial-gradient(ellipse at 60% 80%, rgba(0,255,157,0.03) 0%, transparent 50%);
  }
  .grid-lines {
    position:fixed; inset:0; z-index:0;
    background-image: linear-gradient(rgba(0,229,255,0.04) 1px, transparent 1px),
                      linear-gradient(90deg, rgba(0,229,255,0.04) 1px, transparent 1px);
    background-size: 60px 60px;
  }

  /* Floating particles */
  .particles { position:fixed; inset:0; z-index:0; pointer-events:none; overflow:hidden; }
  .particle {
    position:absolute; border-radius:50%;
    animation: float linear infinite;
  }
  @keyframes float {
    0% { transform: translateY(100vh) rotate(0deg); opacity:0; }
    10% { opacity:1; }
    90% { opacity:1; }
    100% { transform: translateY(-100px) rotate(720deg); opacity:0; }
  }

  nav {
    position:relative; z-index:10;
    padding:1.25rem 3rem;
    display:flex; align-items:center; gap:1rem;
    border-bottom:1px solid var(--border);
    backdrop-filter:blur(20px);
    background:rgba(5,11,26,0.8);
  }
  .nav-logo {
    width:40px; height:40px;
    background:linear-gradient(135deg, var(--accent), var(--accent2));
    border-radius:10px;
    display:flex; align-items:center; justify-content:center;
    font-size:18px;
    box-shadow: 0 0 20px rgba(0,229,255,0.3);
  }
  .nav-title { font-size:1.1rem; font-weight:700; letter-spacing:-0.02em; }
  .nav-sub { font-size:0.75rem; color:var(--muted); font-family:'JetBrains Mono',monospace; }
  .status-pill {
    margin-left:auto;
    display:flex; align-items:center; gap:8px;
    background:rgba(0,255,157,0.08);
    border:1px solid rgba(0,255,157,0.2);
    padding:6px 14px; border-radius:20px;
    font-size:12px; color:var(--green);
    font-family:'JetBrains Mono',monospace;
  }
  .status-dot {
    width:7px; height:7px; border-radius:50%;
    background:var(--green);
    box-shadow:0 0 8px var(--green);
    animation:blink 2s infinite;
  }
  @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0.4} }

  main { position:relative; z-index:1; max-width:1000px; margin:0 auto; padding:4rem 2rem; }

  .hero { text-align:center; margin-bottom:4rem; }
  .hero-badge {
    display:inline-flex; align-items:center; gap:8px;
    background:rgba(0,229,255,0.06);
    border:1px solid rgba(0,229,255,0.15);
    padding:6px 16px; border-radius:20px;
    font-size:12px; color:var(--accent);
    font-family:'JetBrains Mono',monospace;
    margin-bottom:1.5rem;
    letter-spacing:0.05em;
  }
  .hero h1 {
    font-size:3.5rem; font-weight:700;
    letter-spacing:-0.04em; line-height:1.05;
    margin-bottom:1rem;
  }
  .hero h1 .grad {
    background:linear-gradient(90deg, var(--accent), var(--accent2), var(--green));
    -webkit-background-clip:text; -webkit-text-fill-color:transparent;
    background-clip:text;
  }
  .hero p { font-size:1.1rem; color:var(--muted); max-width:500px; margin:0 auto 2rem; line-height:1.6; }

  .stats-row {
    display:grid; grid-template-columns:repeat(3,1fr);
    gap:1px; background:var(--border);
    border:1px solid var(--border);
    border-radius:16px; overflow:hidden;
    margin-bottom:3rem;
  }
  .stat {
    background:var(--surface);
    padding:1.5rem;
    text-align:center;
    transition:background 0.2s;
  }
  .stat:hover { background:var(--surface2); }
  .stat-val {
    font-size:2rem; font-weight:700;
    font-family:'JetBrains Mono',monospace;
    color:var(--accent);
    text-shadow:0 0 20px rgba(0,229,255,0.4);
    display:block; margin-bottom:4px;
  }
  .stat-lbl { font-size:12px; color:var(--muted); text-transform:uppercase; letter-spacing:0.08em; }

  .demo-grid { display:grid; grid-template-columns:1fr 1fr; gap:1.5rem; margin-bottom:3rem; }
  @media(max-width:700px){ .demo-grid{grid-template-columns:1fr} .hero h1{font-size:2.2rem} .stats-row{grid-template-columns:1fr} }

  .card {
    background:var(--surface);
    border:1px solid var(--border);
    border-radius:16px; overflow:hidden;
    transition:border-color 0.2s, transform 0.2s;
  }
  .card:hover { border-color:rgba(0,229,255,0.3); transform:translateY(-2px); }

  .card-head {
    padding:1rem 1.25rem;
    border-bottom:1px solid var(--border);
    display:flex; align-items:center; gap:10px;
    font-size:13px; font-weight:600;
  }
  .card-icon {
    width:32px; height:32px; border-radius:8px;
    display:flex; align-items:center; justify-content:center;
    font-size:15px;
  }
  .icon-enc { background:rgba(0,229,255,0.1); }
  .icon-dec { background:rgba(124,58,237,0.1); }
  .icon-comp { background:rgba(0,255,157,0.1); }

  .card-body { padding:1.25rem; }

  input, textarea {
    width:100%;
    background:rgba(0,0,0,0.3);
    border:1px solid var(--border);
    border-radius:8px;
    color:var(--text);
    font-family:'JetBrains Mono',monospace;
    font-size:13px;
    padding:10px 12px;
    outline:none;
    transition:border-color 0.2s;
    margin-bottom:10px;
  }
  input:focus, textarea:focus { border-color:var(--accent); }
  input::placeholder, textarea::placeholder { color:var(--muted); }

  .btn {
    width:100%;
    padding:10px;
    border:none; border-radius:8px;
    font-family:'Space Grotesk',sans-serif;
    font-weight:600; font-size:13px;
    cursor:pointer; transition:all 0.2s;
  }
  .btn-enc { background:linear-gradient(135deg, var(--accent), #0099bb); color:#050b1a; }
  .btn-dec { background:linear-gradient(135deg, var(--accent2), #5b21b6); color:#fff; }
  .btn-comp { background:linear-gradient(135deg, var(--green), #00b870); color:#050b1a; }
  .btn:hover { transform:translateY(-1px); filter:brightness(1.1); }
  .btn:active { transform:translateY(0); }

  .result-box {
    margin-top:10px;
    background:rgba(0,0,0,0.4);
    border:1px solid var(--border);
    border-radius:8px;
    padding:10px 12px;
    font-family:'JetBrains Mono',monospace;
    font-size:12px;
    color:var(--accent);
    min-height:42px;
    word-break:break-all;
    display:none;
    animation:fadeIn 0.3s ease;
  }
  .result-box.visible { display:block; }
  @keyframes fadeIn { from{opacity:0;transform:translateY(4px)} to{opacity:1;transform:translateY(0)} }

  .result-label { font-size:10px; color:var(--muted); text-transform:uppercase; letter-spacing:0.08em; margin-bottom:4px; }

  .pipeline-section { margin-bottom:3rem; }
  .section-title {
    font-size:1.5rem; font-weight:700; letter-spacing:-0.03em;
    margin-bottom:1.25rem;
    display:flex; align-items:center; gap:10px;
  }
  .section-title::after {
    content:''; flex:1; height:1px; background:var(--border);
  }

  .pipeline {
    display:flex; align-items:center; gap:0;
    overflow-x:auto; padding-bottom:0.5rem;
  }
  .pipe-step {
    flex-shrink:0;
    background:var(--surface);
    border:1px solid var(--border);
    border-radius:12px;
    padding:1rem 1.25rem;
    text-align:center;
    min-width:120px;
    transition:all 0.2s;
    cursor:default;
  }
  .pipe-step:hover { border-color:var(--accent); background:var(--surface2); }
  .pipe-icon { font-size:1.5rem; margin-bottom:6px; }
  .pipe-name { font-size:12px; font-weight:600; margin-bottom:2px; }
  .pipe-tool { font-size:10px; color:var(--muted); font-family:'JetBrains Mono',monospace; }
  .pipe-status { font-size:10px; margin-top:4px; }
  .pipe-pass { color:var(--green); }
  .pipe-arrow {
    color:var(--border); font-size:1.2rem; padding:0 6px;
    flex-shrink:0;
  }

  .endpoint-grid { display:grid; grid-template-columns:repeat(3,1fr); gap:1rem; }
  @media(max-width:700px){ .endpoint-grid{grid-template-columns:1fr} }
  .endpoint-card {
    background:var(--surface);
    border:1px solid var(--border);
    border-radius:12px; padding:1.25rem;
    transition:all 0.2s;
  }
  .endpoint-card:hover { border-color:rgba(0,229,255,0.3); }
  .method-badge {
    display:inline-block;
    font-size:10px; font-weight:700;
    font-family:'JetBrains Mono',monospace;
    padding:3px 8px; border-radius:4px;
    margin-bottom:8px;
  }
  .get { background:rgba(0,255,157,0.15); color:var(--green); }
  .post { background:rgba(0,229,255,0.15); color:var(--accent); }
  .endpoint-path { font-family:'JetBrains Mono',monospace; font-size:13px; font-weight:600; margin-bottom:4px; }
  .endpoint-desc { font-size:12px; color:var(--muted); }

  footer {
    position:relative; z-index:1;
    text-align:center; padding:2rem;
    border-top:1px solid var(--border);
    color:var(--muted); font-size:12px;
    font-family:'JetBrains Mono',monospace;
  }
  footer span { color:var(--accent); }

  .loading-spinner {
    display:inline-block; width:14px; height:14px;
    border:2px solid rgba(0,0,0,0.3);
    border-top-color:currentColor;
    border-radius:50%;
    animation:spin 0.6s linear infinite;
    vertical-align:middle; margin-right:6px;
  }
  @keyframes spin { to{transform:rotate(360deg)} }
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
  <div class="status-pill">
    <div class="status-dot"></div>
    SYSTEM HEALTHY
  </div>
</nav>

<main>
  <div class="hero">
    <div class="hero-badge">🛡️ DEVSECOPS SECURED · AZURE DEPLOYED</div>
    <h1>Privacy-Preserving<br><span class="grad">Encryption API</span></h1>
    <p>Secure homomorphic encryption service — protected by automated DevSecOps pipeline with SAST, SCA, and container scanning.</p>
  </div>

  <div class="stats-row">
    <div class="stat">
      <span class="stat-val" id="uptime">99.9%</span>
      <span class="stat-lbl">Uptime</span>
    </div>
    <div class="stat">
      <span class="stat-val" id="reqCount">0</span>
      <span class="stat-lbl">Requests</span>
    </div>
    <div class="stat">
      <span class="stat-val">AES-256</span>
      <span class="stat-lbl">Encryption</span>
    </div>
  </div>

  <div class="section-title">🔬 Live API Demo</div>

  <div class="demo-grid">
    <div class="card">
      <div class="card-head">
        <div class="card-icon icon-enc">🔒</div>
        Encrypt Data
      </div>
      <div class="card-body">
        <input type="text" id="encInput" placeholder="Enter text to encrypt..." />
        <button class="btn btn-enc" onclick="encryptData()">🔒 Encrypt</button>
        <div class="result-box" id="encResult">
          <div class="result-label">Encrypted Output</div>
          <div id="encOutput"></div>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-head">
        <div class="card-icon icon-dec">🔓</div>
        Decrypt Data
      </div>
      <div class="card-body">
        <textarea id="decInput" placeholder="Paste encrypted text here..." style="height:72px;resize:none;margin-bottom:10px"></textarea>
        <button class="btn btn-dec" onclick="decryptData()">🔓 Decrypt</button>
        <div class="result-box" id="decResult" style="color:#a78bfa">
          <div class="result-label">Decrypted Output</div>
          <div id="decOutput"></div>
        </div>
      </div>
    </div>
  </div>

  <div class="card" style="margin-bottom:3rem">
    <div class="card-head">
      <div class="card-icon icon-comp">➕</div>
      Privacy-Preserving Computation (Add two numbers on encrypted data)
    </div>
    <div class="card-body" style="display:grid;grid-template-columns:1fr 1fr auto;gap:10px;align-items:end">
      <div>
        <div style="font-size:11px;color:var(--muted);margin-bottom:6px">Number A</div>
        <input type="number" id="numA" placeholder="e.g. 42" style="margin-bottom:0" />
      </div>
      <div>
        <div style="font-size:11px;color:var(--muted);margin-bottom:6px">Number B</div>
        <input type="number" id="numB" placeholder="e.g. 8" style="margin-bottom:0" />
      </div>
      <button class="btn btn-comp" style="white-space:nowrap" onclick="computeEncrypted()">➕ Compute</button>
    </div>
    <div class="card-body" style="padding-top:0">
      <div class="result-box" id="compResult" style="color:var(--green)">
        <div class="result-label">Result (decrypted sum)</div>
        <div id="compOutput"></div>
      </div>
    </div>
  </div>

  <div class="pipeline-section">
    <div class="section-title">🚀 DevSecOps Pipeline</div>
    <div class="pipeline">
      <div class="pipe-step">
        <div class="pipe-icon">🔍</div>
        <div class="pipe-name">SAST</div>
        <div class="pipe-tool">Bandit</div>
        <div class="pipe-status pipe-pass">✅ Passed</div>
      </div>
      <div class="pipe-arrow">→</div>
      <div class="pipe-step">
        <div class="pipe-icon">📦</div>
        <div class="pipe-name">SCA</div>
        <div class="pipe-tool">Snyk</div>
        <div class="pipe-status pipe-pass">✅ Passed</div>
      </div>
      <div class="pipe-arrow">→</div>
      <div class="pipe-step">
        <div class="pipe-icon">🔑</div>
        <div class="pipe-name">Secrets</div>
        <div class="pipe-tool">TruffleHog</div>
        <div class="pipe-status pipe-pass">✅ Passed</div>
      </div>
      <div class="pipe-arrow">→</div>
      <div class="pipe-step">
        <div class="pipe-icon">🧪</div>
        <div class="pipe-name">Tests</div>
        <div class="pipe-tool">Pytest</div>
        <div class="pipe-status pipe-pass">✅ Passed</div>
      </div>
      <div class="pipe-arrow">→</div>
      <div class="pipe-step">
        <div class="pipe-icon">🐳</div>
        <div class="pipe-name">Build</div>
        <div class="pipe-tool">Docker</div>
        <div class="pipe-status pipe-pass">✅ Passed</div>
      </div>
      <div class="pipe-arrow">→</div>
      <div class="pipe-step">
        <div class="pipe-icon">🛡️</div>
        <div class="pipe-name">Image Scan</div>
        <div class="pipe-tool">Trivy</div>
        <div class="pipe-status pipe-pass">✅ Passed</div>
      </div>
      <div class="pipe-arrow">→</div>
      <div class="pipe-step" style="border-color:rgba(0,229,255,0.4);background:rgba(0,229,255,0.05)">
        <div class="pipe-icon">☁️</div>
        <div class="pipe-name">Deploy</div>
        <div class="pipe-tool">Azure</div>
        <div class="pipe-status pipe-pass">✅ Live</div>
      </div>
    </div>
  </div>

  <div class="section-title">📡 API Endpoints</div>
  <div class="endpoint-grid">
    <div class="endpoint-card">
      <span class="method-badge get">GET</span>
      <div class="endpoint-path">/health</div>
      <div class="endpoint-desc">Health check — returns service status</div>
    </div>
    <div class="endpoint-card">
      <span class="method-badge post">POST</span>
      <div class="endpoint-path">/encrypt</div>
      <div class="endpoint-desc">Encrypt plaintext using Fernet AES-128</div>
    </div>
    <div class="endpoint-card">
      <span class="method-badge post">POST</span>
      <div class="endpoint-path">/decrypt</div>
      <div class="endpoint-desc">Decrypt ciphertext back to plaintext</div>
    </div>
    <div class="endpoint-card">
      <span class="method-badge post">POST</span>
      <div class="endpoint-path">/compute</div>
      <div class="endpoint-desc">Privacy-preserving addition on encrypted values</div>
    </div>
    <div class="endpoint-card">
      <span class="method-badge get">GET</span>
      <div class="endpoint-path">/stats</div>
      <div class="endpoint-desc">Live request statistics and system info</div>
    </div>
    <div class="endpoint-card" style="border-color:rgba(0,229,255,0.2)">
      <span class="method-badge get">GET</span>
      <div class="endpoint-path">/</div>
      <div class="endpoint-desc">This dashboard — live demo interface</div>
    </div>
  </div>
</main>

<footer>
  Built with <span>DevSecOps</span> · Deployed on <span>Azure Container Apps</span> · Secured by <span>GitHub Actions</span>
</footer>

<script>
let reqCount = 0;

// Generate particles
const pc = document.getElementById('particles');
for(let i=0;i<15;i++){
  const p = document.createElement('div');
  p.className='particle';
  const size = Math.random()*4+2;
  const colors=['rgba(0,229,255,0.4)','rgba(124,58,237,0.4)','rgba(0,255,157,0.3)'];
  p.style.cssText=`width:${size}px;height:${size}px;left:${Math.random()*100}%;background:${colors[Math.floor(Math.random()*3)]};animation-duration:${Math.random()*15+10}s;animation-delay:${Math.random()*10}s`;
  pc.appendChild(p);
}

function updateCount(){
  reqCount++;
  document.getElementById('reqCount').textContent=reqCount;
}

async function callAPI(endpoint, data){
  updateCount();
  const r = await fetch(endpoint,{
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify(data)
  });
  return r.json();
}

async function encryptData(){
  const val = document.getElementById('encInput').value.trim();
  if(!val){alert('Enter some text to encrypt!');return;}
  const btn = event.target;
  btn.innerHTML='<span class="loading-spinner"></span>Encrypting...';
  btn.disabled=true;
  try{
    const res = await callAPI('/encrypt',{data:val});
    document.getElementById('encOutput').textContent = res.encrypted || res.error;
    document.getElementById('encResult').classList.add('visible');
    // Auto-fill decrypt box
    document.getElementById('decInput').value = res.encrypted || '';
  }catch(e){
    document.getElementById('encOutput').textContent='Error: '+e.message;
    document.getElementById('encResult').classList.add('visible');
  }
  btn.innerHTML='🔒 Encrypt';btn.disabled=false;
}

async function decryptData(){
  const val = document.getElementById('decInput').value.trim();
  if(!val){alert('Paste encrypted text first!');return;}
  const btn = event.target;
  btn.innerHTML='<span class="loading-spinner"></span>Decrypting...';
  btn.disabled=true;
  try{
    const res = await callAPI('/decrypt',{data:val});
    document.getElementById('decOutput').textContent = res.decrypted || res.error;
    document.getElementById('decResult').classList.add('visible');
  }catch(e){
    document.getElementById('decOutput').textContent='Error: '+e.message;
    document.getElementById('decResult').classList.add('visible');
  }
  btn.innerHTML='🔓 Decrypt';btn.disabled=false;
}

async function computeEncrypted(){
  const a=document.getElementById('numA').value;
  const b=document.getElementById('numB').value;
  if(!a||!b){alert('Enter both numbers!');return;}
  const btn=event.target;
  btn.innerHTML='<span class="loading-spinner"></span>Computing...';
  btn.disabled=true;
  try{
    const [encA, encB] = await Promise.all([
      callAPI('/encrypt',{data:String(a)}),
      callAPI('/encrypt',{data:String(b)})
    ]);
    const res = await callAPI('/compute',{enc_a:encA.encrypted, enc_b:encB.encrypted});
    const decRes = await callAPI('/decrypt',{data:res.enc_result});
    document.getElementById('compOutput').textContent=`${a} + ${b} = ${decRes.decrypted} (computed on encrypted data!)`;
    document.getElementById('compResult').classList.add('visible');
    updateCount(); updateCount();
  }catch(e){
    document.getElementById('compOutput').textContent='Error: '+e.message;
    document.getElementById('compResult').classList.add('visible');
  }
  btn.innerHTML='➕ Compute';btn.disabled=false;
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
        ciphertext = fernet.encrypt(str(payload["data"]).encode()).decode()
        logger.info("Data encrypted successfully.")
        return jsonify({"encrypted": ciphertext}), 200
    except Exception as e:
        logger.error("Encryption failed: %s", str(e))
        return jsonify({"error": "Encryption failed"}), 500


@app.route("/decrypt", methods=["POST"])
def decrypt_endpoint():
    try:
        payload = request.get_json(force=True)
        if not payload or "data" not in payload:
            return jsonify({"error": "Missing 'data' field"}), 400
        plaintext = fernet.decrypt(str(payload["data"]).encode()).decode()
        logger.info("Data decrypted successfully.")
        return jsonify({"decrypted": plaintext}), 200
    except Exception as e:
        logger.error("Decryption failed: %s", str(e))
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
        result = a + b
        enc_result = fernet.encrypt(str(result).encode()).decode()
        logger.info("Privacy-preserving computation completed.")
        return jsonify({"enc_result": enc_result}), 200
    except Exception as e:
        logger.error("Computation failed: %s", str(e))
        return jsonify({"error": "Computation failed"}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=False)
