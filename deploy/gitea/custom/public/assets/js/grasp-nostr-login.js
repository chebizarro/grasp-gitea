(() => {
  const bridgeURL = window.GRASP_BRIDGE_PUBLIC_URL || 'https://grasp.sharegap.net';

  function onLoginPage() {
    return window.location.pathname === '/user/login' || window.location.pathname === '/user/sign_in';
  }

  function targetRedirect() {
    const next = new URLSearchParams(window.location.search).get('redirect_to');
    return next || '/';
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
    if (!challengeResp.ok) throw new Error(`challenge failed: ${challengeResp.status}`);
    const challenge = await challengeResp.json();

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
    if (!verifyResp.ok || !result.ok) throw new Error(result.error || `verify failed: ${verifyResp.status}`);

    // Bridge verification has created/linked the Gitea identity. The deployed
    // Gitea session handoff should consume the resolved identity and establish
    // the web session; until then, this lands on the normal post-login target.
    status(`Verified ${result.identity.gitea_user}; completing Gitea session…`);
    window.location.assign(result.redirect_uri || targetRedirect());
  }

  async function nip46Login() {
    const input = document.getElementById('grasp-bunker-uri');
    const bunkerURI = input && input.value.trim();
    if (!bunkerURI) {
      status('Paste a Signet bunker URI first.', true);
      return;
    }
    const initResp = await fetch(`${bridgeURL}/auth/nip46/init`, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({bunker_uri: bunkerURI, redirect_uri: targetRedirect()}),
    });
    const init = await initResp.json();
    if (!initResp.ok) throw new Error(init.error || `NIP-46 init failed: ${initResp.status}`);
    status('Waiting for bunker approval…');
    const deadline = Date.now() + 120000;
    while (Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 1500));
      const poll = await fetch(init.poll_url);
      const state = await poll.json();
      if (state.status === 'complete') {
        status(`Verified ${state.identity.gitea_user}; completing Gitea session…`);
        window.location.assign(state.redirect_uri || targetRedirect());
        return;
      }
      if (state.status === 'error') throw new Error(state.error || 'NIP-46 login failed');
    }
    throw new Error('NIP-46 login timed out');
  }

  function wire() {
    if (!onLoginPage() || !insertPanel()) return;
    document.getElementById('grasp-nip07-login').addEventListener('click', () => nip07Login().catch((err) => status(err.message, true)));
    document.getElementById('grasp-nip46-login').addEventListener('click', () => nip46Login().catch((err) => status(err.message, true)));
    document.getElementById('grasp-nip55-login').addEventListener('click', (event) => {
      event.preventDefault();
      const u = new URL(`${bridgeURL}/auth/nip55/challenge`);
      u.searchParams.set('redirect_uri', targetRedirect());
      window.location.assign(u.toString());
    });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', wire);
  else wire();
})();
