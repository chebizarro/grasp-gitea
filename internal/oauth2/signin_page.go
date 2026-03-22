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
    max-width: 380px;
    text-align: center;
  }
  .logo {
    font-size: 2rem;
    margin-bottom: 0.5rem;
  }
  h1 { font-size: 1.25rem; font-weight: 600; margin-bottom: 0.25rem; }
  .subtitle { font-size: 0.875rem; color: #8b949e; margin-bottom: 2rem; }
  #btn-sign-in {
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
  #btn-sign-in:hover:not(:disabled) { background: #8a5cd0; }
  #btn-sign-in:disabled { opacity: 0.6; cursor: not-allowed; }
  #status {
    margin-top: 1.25rem;
    font-size: 0.875rem;
    min-height: 1.25rem;
    color: #8b949e;
  }
  #status.error { color: #f85149; }
  #status.success { color: #3fb950; }
  .no-ext {
    margin-top: 1rem;
    padding: 0.75rem;
    background: #1c2128;
    border: 1px solid #30363d;
    border-radius: 8px;
    font-size: 0.8125rem;
    color: #8b949e;
    display: none;
  }
  .no-ext a { color: #58a6ff; text-decoration: none; }
  .no-ext a:hover { text-decoration: underline; }
  .footer { margin-top: 1.5rem; font-size: 0.75rem; color: #484f58; }
</style>
</head>
<body>
<div class="card">
  <div class="logo">⚡</div>
  <h1>Sign in with Nostr</h1>
  <p class="subtitle">Use your NIP-07 browser extension to authenticate</p>

  <button id="btn-sign-in" onclick="signIn()">
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/></svg>
    Sign in with Nostr
  </button>

  <div id="status"></div>

  <div class="no-ext" id="no-ext">
    No NIP-07 extension detected. Install one to continue:
    <br><br>
    <a href="https://getalby.com" target="_blank" rel="noopener">Alby</a> ·
    <a href="https://github.com/fiatjaf/nos2x" target="_blank" rel="noopener">nos2x</a> ·
    <a href="https://github.com/susumuota/nostr-keyx" target="_blank" rel="noopener">nostr-keyx</a>
  </div>

  <p class="footer">Powered by GRASP-Gitea</p>
</div>

<script>
const CHALLENGE = __CHALLENGE_DATA__;

function setStatus(msg, cls) {
  const el = document.getElementById('status');
  el.textContent = msg;
  el.className = cls || '';
}

function setLoading(loading) {
  const btn = document.getElementById('btn-sign-in');
  btn.disabled = loading;
  btn.textContent = loading ? 'Signing in…' : '⚡ Sign in with Nostr';
}

async function signIn() {
  if (!window.nostr) {
    document.getElementById('no-ext').style.display = 'block';
    setStatus('No NIP-07 extension found.', 'error');
    return;
  }

  setLoading(true);
  setStatus('Requesting pubkey…');

  try {
    const pubkey = await window.nostr.getPublicKey();
    if (!pubkey) throw new Error('Extension returned no pubkey.');

    setStatus('Waiting for signature…');

    const event = {
      kind: 27235,
      created_at: Math.floor(Date.now() / 1000),
      tags: [
        ['u', CHALLENGE.url],
        ['method', CHALLENGE.method],
      ],
      content: '',
      pubkey,
    };

    const signed = await window.nostr.signEvent(event);
    if (!signed) throw new Error('Extension rejected signing request.');

    setStatus('Verifying…');

    const resp = await fetch(CHALLENGE.url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        challenge_id: CHALLENGE.challenge_id,
        signed_event: JSON.stringify(signed),
      }),
    });

    const body = await resp.json();

    if (!resp.ok) {
      throw new Error(body.error || 'Verification failed.');
    }

    setStatus('Redirecting…', 'success');
    window.location.href = body.redirect_url;

  } catch (err) {
    setLoading(false);
    if (err.message && err.message.includes('User rejected')) {
      setStatus('You rejected the signing request.', 'error');
    } else {
      setStatus(err.message || 'An error occurred.', 'error');
    }
  }
}

// Auto-detect extension on load
window.addEventListener('DOMContentLoaded', function() {
  const expires = new Date(CHALLENGE.expires_at * 1000);
  if (Date.now() > expires) {
    setStatus('This login link has expired. Please go back and try again.', 'error');
    document.getElementById('btn-sign-in').disabled = true;
    return;
  }
  if (!window.nostr) {
    document.getElementById('no-ext').style.display = 'block';
  }
});
</script>
</body>
</html>`
