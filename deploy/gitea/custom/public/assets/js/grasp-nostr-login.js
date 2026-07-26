(() => {
  const bridgeURL = (window.GRASP_BRIDGE_PUBLIC_URL || window.location.origin).replace(/\/$/, '');

  function onLoginPage() {
    return window.location.pathname === '/user/login' || window.location.pathname === '/user/sign_in';
  }

  function targetRedirect() {
    const raw = new URLSearchParams(window.location.search).get('redirect_to');
    if (!raw || !raw.startsWith('/') || raw.startsWith('//') || raw.includes('\\')) return '/';
    try {
      const target = new URL(raw, window.location.origin);
      if (target.origin !== window.location.origin ||
          target.pathname === '/auth/session/handoff' ||
          target.pathname.startsWith('/auth/session/handoff/')) return '/';
      return target.pathname + target.search;
    } catch {
      return '/';
    }
  }

  function insertPanel() {
    const form = document.querySelector('form[action*="/user/login"], form[action*="/user/sign_in"]');
    if (!form || document.getElementById('grasp-nostr-login')) return null;

    const panel = document.createElement('div');
    panel.id = 'grasp-nostr-login';
    panel.className = 'ui segment';
    panel.innerHTML = `
      <button type="button" class="ui fluid primary button" id="grasp-nip07-login">Sign in with Nostr</button>
      <div class="ui small message" id="grasp-nostr-status" style="display:none"></div>
      <details class="ui small message" style="margin-top:0.75rem">
        <summary>Remote signer / Android signer</summary>
        <div class="field" style="margin-top:0.75rem">
          <input id="grasp-bunker-uri" type="text" placeholder="bunker://...">
        </div>
        <button type="button" class="ui button" id="grasp-nip46-login">Connect Signet bunker</button>
        <a class="ui button" id="grasp-nip55-login" href="#">Android signer</a>
      </details>`;
    form.parentElement.insertBefore(panel, form);
    return panel;
  }

  function status(text, isError = false) {
    const el = document.getElementById('grasp-nostr-status');
    if (!el) return;
    el.style.display = '';
    el.classList.toggle('negative', isError);
    el.classList.toggle('positive', !isError);
    el.textContent = text;
  }

  async function nip07Login() {
    if (!window.nostr) {
      status('No NIP-07 extension found. Install one or use the remote signer option.', true);
      return;
    }
    status('Requesting Nostr pubkey…');
    await window.nostr.getPublicKey();

    const challengeResp = await fetch(`${bridgeURL}/auth/nip07/challenge`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({redirect_uri: targetRedirect()}),
    });
    const challenge = await challengeResp.json();
    if (!challengeResp.ok) throw new Error(challenge.error || `challenge failed: ${challengeResp.status}`);

    status('Requesting Nostr signature…');
    const event = await window.nostr.signEvent({
      kind: 27235,
      created_at: Math.floor(Date.now() / 1000),
      tags: [['u', challenge.url], ['method', challenge.method], ['nonce', challenge.nonce]],
      content: '',
    });

    const verifyResp = await fetch(`${bridgeURL}/auth/nip07/verify`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({signed_event: event}),
    });
    const result = await verifyResp.json();
    if (!verifyResp.ok || !result.ok || !result.handoff_url) {
      throw new Error(result.error || `verify failed: ${verifyResp.status}`);
    }

    status(`Verified ${result.identity.gitea_user}; completing Gitea session…`);
    window.location.assign(result.handoff_url);
  }

  async function nip46Login() {
    const input = document.getElementById('grasp-bunker-uri');
    const bunkerURI = input && input.value.trim();
    if (!bunkerURI) {
      status('Paste a Signet bunker URI first.', true);
      return;
    }
    const bindResp = await fetch(`${bridgeURL}/auth/session/nip46/bind`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({redirect_uri: targetRedirect()}),
    });
    const binding = await bindResp.json();
    if (!bindResp.ok || !binding.redirect_uri) {
      throw new Error(binding.error || `NIP-46 binding failed: ${bindResp.status}`);
    }

    const initResp = await fetch(`${bridgeURL}/auth/nip46/init`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({bunker_uri: bunkerURI, redirect_uri: binding.redirect_uri}),
    });
    const init = await initResp.json();
    if (!initResp.ok) throw new Error(init.error || `NIP-46 init failed: ${initResp.status}`);
    status('Waiting for bunker approval…');
    const deadline = Date.now() + 120000;
    while (Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 1500));
      const safeStatusURL = new URL(`${bridgeURL}/auth/session/nip46/status`);
      safeStatusURL.searchParams.set('session', init.session_token);
      const poll = await fetch(safeStatusURL);
      const state = await poll.json();
      if (state.status === 'complete') {
        const exchangeResp = await fetch(`${bridgeURL}/auth/session/nip46/exchange`, {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({session_token: init.session_token}),
        });
        const handoff = await exchangeResp.json();
        if (!exchangeResp.ok || !handoff.handoff_url) {
          throw new Error(handoff.error || `session exchange failed: ${exchangeResp.status}`);
        }
        status(`Verified ${state.identity.gitea_user}; completing Gitea session…`);
        window.location.assign(handoff.handoff_url);
        return;
      }
      if (state.status === 'error') throw new Error(state.error || 'NIP-46 login failed');
    }
    throw new Error('NIP-46 login timed out');
  }

  async function nip55Login() {
    const challengeURL = new URL(`${bridgeURL}/auth/nip55/challenge`);
    challengeURL.searchParams.set('redirect_uri', targetRedirect());
    const response = await fetch(challengeURL);
    const challenge = await response.json();
    if (!response.ok || !challenge.nostrsigner_uri) {
      throw new Error(challenge.error || `NIP-55 challenge failed: ${response.status}`);
    }
    window.location.assign(challenge.nostrsigner_uri);
  }

  function wire() {
    if (!onLoginPage() || !insertPanel()) return;
    document.getElementById('grasp-nip07-login').addEventListener('click', () => nip07Login().catch((err) => status(err.message, true)));
    document.getElementById('grasp-nip46-login').addEventListener('click', () => nip46Login().catch((err) => status(err.message, true)));
    document.getElementById('grasp-nip55-login').addEventListener('click', (event) => {
      event.preventDefault();
      nip55Login().catch((err) => status(err.message, true));
    });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', wire);
  else wire();
})();
