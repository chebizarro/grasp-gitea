package oauth2

// signinPageTemplate is the HTML served at the OAuth2 authorize endpoint.
// The Go handler replaces __CHALLENGE_DATA__ with a JSON object.
const signinPageTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sign in with Nostr</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    background: #0d1117;
    color: #c9d1d9;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
  }
  .card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 12px;
    padding: 2.5rem 2rem;
    width: 100%;
    max-width: 440px;
  }
  .logo { font-size: 2rem; text-align: center; margin-bottom: 0.5rem; }
  h1 { font-size: 1.25rem; font-weight: 600; margin-bottom: 0.25rem; text-align: center; }
  .subtitle { font-size: 0.875rem; color: #8b949e; margin-bottom: 1.5rem; text-align: center; }

  /* Tabs */
  .tabs { display: flex; border-bottom: 1px solid #30363d; margin-bottom: 1.5rem; }
  .tab {
    flex: 1;
    padding: 0.6rem 0.5rem;
    background: none;
    border: none;
    border-bottom: 2px solid transparent;
    color: #8b949e;
    font-size: 0.8125rem;
    font-weight: 500;
    cursor: pointer;
    transition: color 0.15s, border-color 0.15s;
  }
  .tab:hover { color: #c9d1d9; }
  .tab.active { color: #e6edf3; border-bottom-color: #6f42c1; }
  .tab-panel { display: none; }
  .tab-panel.active { display: block; }

  /* Buttons */
  .btn-primary {
    width: 100%;
    padding: 0.75rem 1rem;
    background: #6f42c1;
    color: #fff;
    border: none;
    border-radius: 8px;
    font-size: 1rem;
    font-weight: 600;
    cursor: pointer;
    transition: background 0.15s;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.5rem;
  }
  .btn-primary:hover:not(:disabled) { background: #8a5cd0; }
  .btn-primary:disabled { opacity: 0.6; cursor: not-allowed; }
  .btn-secondary {
    width: 100%;
    padding: 0.6rem 1rem;
    background: #21262d;
    color: #c9d1d9;
    border: 1px solid #30363d;
    border-radius: 8px;
    font-size: 0.875rem;
    font-weight: 500;
    cursor: pointer;
    transition: background 0.15s;
    margin-top: 0.5rem;
  }
  .btn-secondary:hover { background: #30363d; }

  /* Inputs */
  .input-group { margin-bottom: 1rem; }
  .input-group label { display: block; font-size: 0.8125rem; color: #8b949e; margin-bottom: 0.4rem; }
  .input-group input {
    width: 100%;
    padding: 0.6rem 0.75rem;
    background: #0d1117;
    border: 1px solid #30363d;
    border-radius: 6px;
    color: #e6edf3;
    font-size: 0.9rem;
    font-family: monospace;
  }
  .input-group input:focus { outline: none; border-color: #6f42c1; }
  .input-group input::placeholder { color: #484f58; }

  /* Status */
  .status {
    margin-top: 1rem;
    font-size: 0.875rem;
    min-height: 1.25rem;
    color: #8b949e;
    text-align: center;
  }
  .status.error { color: #f85149; }
  .status.success { color: #3fb950; }

  /* Info box */
  .info-box {
    margin-top: 1rem;
    padding: 0.75rem;
    background: #1c2128;
    border: 1px solid #30363d;
    border-radius: 8px;
    font-size: 0.8125rem;
    color: #8b949e;
  }
  .info-box a { color: #58a6ff; text-decoration: none; }
  .info-box a:hover { text-decoration: underline; }

  /* QR code */
  .qr-wrap { text-align: center; margin: 1rem 0; }
  .qr-wrap canvas, .qr-wrap img { border-radius: 6px; }

  /* Spinner */
  .spinner {
    display: inline-block;
    width: 1em; height: 1em;
    border: 2px solid rgba(255,255,255,0.3);
    border-top-color: #fff;
    border-radius: 50%;
    animation: spin 0.7s linear infinite;
    vertical-align: middle;
  }
  @keyframes spin { to { transform: rotate(360deg); } }

  .footer { margin-top: 1.5rem; font-size: 0.75rem; color: #484f58; text-align: center; }
</style>
</head>
<body>
<div class="card">
  <div class="logo">⚡</div>
  <h1>Sign in with Nostr</h1>
  <p class="subtitle">Choose your signing method</p>

  <div class="tabs">
    <button class="tab active" onclick="switchTab('nip07', this)">🔌 Browser Extension</button>
    <button class="tab" onclick="switchTab('nip46', this)">🔐 Remote Signer</button>
    <button class="tab" onclick="switchTab('nip55', this)">📱 Android Signer</button>
  </div>

  <!-- NIP-07: Browser Extension -->
  <div id="panel-nip07" class="tab-panel active">
    <button class="btn-primary" id="btn-nip07" onclick="signInNIP07()">
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/></svg>
      Sign in with Extension
    </button>
    <div class="status" id="status-nip07"></div>
    <div class="info-box" id="no-ext" style="display:none">
      No NIP-07 extension detected. Install one:<br><br>
      <a href="https://getalby.com" target="_blank" rel="noopener">Alby</a> ·
      <a href="https://github.com/fiatjaf/nos2x" target="_blank" rel="noopener">nos2x</a> ·
      <a href="https://github.com/susumuota/nostr-keyx" target="_blank" rel="noopener">nostr-keyx</a>
    </div>
  </div>

  <!-- NIP-46: Remote Signer / Bunker -->
  <div id="panel-nip46" class="tab-panel">
    <div class="input-group">
      <label for="bunker-uri">Bunker URI or NIP-05</label>
      <input type="text" id="bunker-uri" placeholder="bunker://pubkey?relay=wss://...&secret=..." autocomplete="off" />
    </div>
    <button class="btn-primary" id="btn-nip46" onclick="signInNIP46()">
      🔐 Connect Bunker
    </button>
    <div class="status" id="status-nip46"></div>
    <div class="info-box" style="margin-top:1rem">
      Use a NIP-46 compatible signer like
      <a href="https://github.com/greenart7c3/Amber" target="_blank" rel="noopener">Amber</a>,
      <a href="https://nsec.app" target="_blank" rel="noopener">nsec.app</a>, or a local
      <a href="https://github.com/fiatjaf/signet" target="_blank" rel="noopener">Signet</a> bunker.
    </div>
  </div>

  <!-- NIP-55: Android Signer -->
  <div id="panel-nip55" class="tab-panel">
    <p style="font-size:0.875rem;color:#8b949e;margin-bottom:1rem">
      Scan the QR code with an Android NIP-55 signer app, or tap the button below to open it directly.
    </p>
    <button class="btn-primary" id="btn-nip55" onclick="initNIP55()">
      📱 Generate QR Code
    </button>
    <div class="status" id="status-nip55"></div>
    <div id="qr-wrap" class="qr-wrap" style="display:none">
      <canvas id="qr-canvas"></canvas>
    </div>
    <div id="nip55-deeplink-wrap" style="display:none;margin-top:0.75rem">
      <a id="nip55-deeplink" class="btn-secondary" style="text-decoration:none;text-align:center;display:block">
        Open in Signer App
      </a>
    </div>
    <div class="info-box" style="margin-top:1rem">
      Compatible with
      <a href="https://github.com/greenart7c3/Amber" target="_blank" rel="noopener">Amber</a>
      and other NIP-55 Android signer apps.
    </div>
  </div>

  <p class="footer">Powered by GRASP-Gitea · <a href="https://github.com/nostr-protocol/nostr" style="color:#484f58" target="_blank">Nostr</a></p>
</div>

<!-- Minimal QR code library (pure JS, no external fetch) -->
<script>
/* qrcode-generator by kazuhikoarase, MIT license — inlined minimal version */
/* jshint ignore:start */
var qrcode=function(){var a=function(){var a=function(a){this[0]=[];this[1]=[];this[0][0]={},this[1][0]={};var b=a;this.get=function(a){var c=0;return this[0][a]?c|=1:this[1][a]&&(c|=2),c},this.put=function(a,b){this[0][a]=!!(b&1),this[1][a]=!!(b&2)},this.getLengthInBits=function(){return b}};return{glog:function(a){if(a<1)throw new Error("glog("+a+")");return c[a]},gexp:function(a){for(;a<0;)a+=255;for(;a>=256;)a-=255;return b[a]},b:b,c:c}}();function b(a){var b,c=[],d=0;function e(){var a=0;for(var b=0;b<c.length;b++)a+=c[b].getLengthInBits();return a}function f(){return{totalCount:a,dataCount:a-b}}this.getBuffer=function(){return c},this.getEncodedNumber=function(){return d},this.get=function(a){var b=Math.floor(a/8);return 1==(c[b]>>>7-a%8&1)},this.put=function(a,b){for(var c=0;c<b;c++)this.putBit(1==(a>>>b-c-1&1))},this.getLengthInBits=function(){return e()},this.putBit=function(a){var b=Math.floor(d/8);c.length<=b&&c.push(0),a&&(c[b]|=128>>>d%8),d++}}var c=[],d=[],e={};return e}();
// QR generation is handled below with a simpler approach
</script>

<script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js" onerror="window._qrFailed=true"></script>

<script>
const CHALLENGE = __CHALLENGE_DATA__;

// ---- Tab switching ----
function switchTab(name, el) {
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-panel').forEach(p => p.classList.remove('active'));
  el.classList.add('active');
  document.getElementById('panel-' + name).classList.add('active');
}

// ---- Shared helpers ----
function setStatus(id, msg, cls) {
  const el = document.getElementById('status-' + id);
  if (!el) return;
  el.textContent = msg;
  el.className = 'status ' + (cls || '');
}

function setLoading(id, loading, label) {
  const btn = document.getElementById('btn-' + id);
  if (!btn) return;
  btn.disabled = loading;
  if (loading) {
    btn.innerHTML = '<span class="spinner"></span> ' + (label || 'Working…');
  } else {
    btn.textContent = label || btn.dataset.label || 'Try again';
  }
}

function buildRedirectURL(baseRedirectURI, code, state) {
  const sep = baseRedirectURI.includes('?') ? '&' : '?';
  let url = baseRedirectURI + sep + 'code=' + encodeURIComponent(code);
  if (state) url += '&state=' + encodeURIComponent(state);
  return url;
}

// ---- NIP-07: Browser extension ----
async function signInNIP07() {
  if (!window.nostr) {
    document.getElementById('no-ext').style.display = 'block';
    setStatus('nip07', 'No NIP-07 extension found.', 'error');
    return;
  }
  setLoading('nip07', true, 'Requesting pubkey…');
  setStatus('nip07', 'Requesting pubkey…');
  try {
    const pubkey = await window.nostr.getPublicKey();
    if (!pubkey) throw new Error('Extension returned no pubkey.');
    setStatus('nip07', 'Waiting for signature…');
    const event = {
      kind: 27235,
      created_at: Math.floor(Date.now() / 1000),
      tags: [['u', CHALLENGE.url], ['method', CHALLENGE.method]],
      content: '',
      pubkey,
    };
    const signed = await window.nostr.signEvent(event);
    if (!signed) throw new Error('Extension rejected signing request.');
    setStatus('nip07', 'Verifying…');
    const resp = await fetch(CHALLENGE.url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ challenge_id: CHALLENGE.challenge_id, signed_event: JSON.stringify(signed) }),
    });
    const body = await resp.json();
    if (!resp.ok) throw new Error(body.error || 'Verification failed.');
    setStatus('nip07', 'Redirecting…', 'success');
    window.location.href = body.redirect_url;
  } catch(err) {
    setLoading('nip07', false, '⚡ Sign in with Extension');
    setStatus('nip07', err.message || 'An error occurred.', 'error');
  }
}

// ---- NIP-46: Remote signer / bunker ----
let nip46PollTimer = null;

async function signInNIP46() {
  const bunkerURI = document.getElementById('bunker-uri').value.trim();
  if (!bunkerURI) {
    setStatus('nip46', 'Enter a bunker URI or NIP-05 address.', 'error');
    return;
  }
  setLoading('nip46', true, 'Connecting to bunker…');
  setStatus('nip46', 'Initiating remote signing session…');

  // Recover oauth params from the challenge (they were embedded server-side)
  const redirectURI = CHALLENGE.redirect_uri || '';
  const state = CHALLENGE.oauth2_state || '';

  try {
    const resp = await fetch('/auth/nip46/init', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ bunker_uri: bunkerURI, state, redirect_uri: redirectURI }),
    });
    const body = await resp.json();
    if (!resp.ok) throw new Error(body.error || 'Failed to start session.');

    const { session_token, poll_url } = body;
    setStatus('nip46', 'Waiting for approval on your signer… (up to 3 min)');
    pollSession('nip46', poll_url, session_token);
  } catch(err) {
    setLoading('nip46', false, '🔐 Connect Bunker');
    setStatus('nip46', err.message || 'An error occurred.', 'error');
  }
}

function pollSession(tabId, pollURL, sessionToken, attempt) {
  attempt = attempt || 0;
  if (attempt > 180) { // 3 min at 1s interval
    setLoading(tabId, false);
    setStatus(tabId, 'Timed out waiting for signer response.', 'error');
    return;
  }
  setTimeout(async function() {
    try {
      const resp = await fetch(pollURL + '?session=' + encodeURIComponent(sessionToken));
      const body = await resp.json();
      if (body.status === 'complete') {
        setStatus(tabId, 'Redirecting…', 'success');
        window.location.href = body.redirect_url;
      } else if (body.status === 'error') {
        setLoading(tabId, false);
        setStatus(tabId, 'Signer error: ' + (body.error || 'unknown'), 'error');
      } else {
        // still pending
        pollSession(tabId, pollURL, sessionToken, attempt + 1);
      }
    } catch(e) {
      pollSession(tabId, pollURL, sessionToken, attempt + 1);
    }
  }, 1000);
}

// ---- NIP-55: Android signer ----
async function initNIP55() {
  setLoading('nip55', true, 'Generating…');
  setStatus('nip55', 'Generating challenge…');

  const redirectURI = CHALLENGE.redirect_uri || '';
  const state = CHALLENGE.oauth2_state || '';

  try {
    const params = new URLSearchParams({ state, redirect_uri: redirectURI });
    const resp = await fetch('/auth/nip55/challenge?' + params.toString());
    const body = await resp.json();
    if (!resp.ok) throw new Error(body.error || 'Failed to get challenge.');

    const { session_token, nostrsigner_uri, poll_url } = body;

    // Show deep link button
    document.getElementById('nip55-deeplink').href = nostrsigner_uri;
    document.getElementById('nip55-deeplink-wrap').style.display = 'block';

    // Render QR
    const wrap = document.getElementById('qr-wrap');
    wrap.style.display = 'block';
    wrap.innerHTML = '';
    if (window.QRCode) {
      new QRCode(wrap, {
        text: nostrsigner_uri,
        width: 220,
        height: 220,
        colorDark: '#e6edf3',
        colorLight: '#161b22',
        correctLevel: QRCode.CorrectLevel.M,
      });
    } else {
      wrap.innerHTML = '<p style="color:#8b949e;font-size:0.8rem">QR library unavailable — use deep link below</p>';
    }

    setLoading('nip55', false, '🔄 Refresh QR');
    setStatus('nip55', 'Scan or tap the link, then approve in your signer app.');

    // Start polling
    pollSession('nip55', poll_url, session_token);

  } catch(err) {
    setLoading('nip55', false, '📱 Generate QR Code');
    setStatus('nip55', err.message || 'An error occurred.', 'error');
  }
}

// ---- Init ----
window.addEventListener('DOMContentLoaded', function() {
  if (!window.nostr) {
    document.getElementById('no-ext').style.display = 'block';
  }
  // Stash labels
  document.getElementById('btn-nip07').dataset.label = '⚡ Sign in with Extension';
  document.getElementById('btn-nip46').dataset.label = '🔐 Connect Bunker';
  document.getElementById('btn-nip55').dataset.label = '📱 Generate QR Code';
});
</script>
</body>
</html>`
