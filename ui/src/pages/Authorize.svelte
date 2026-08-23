<script>
  import { api } from '../lib/api.js';
  import Login from '../lib/Login.svelte';

  const txnId = new URLSearchParams(window.location.search).get('txn');

  let txn = $state(null);
  let username = $state(null);
  let loading = $state(true);
  let error = $state('');
  let busy = $state(false);

  $effect(() => {
    load();
  });

  async function load() {
    if (!txnId) {
      error = 'Missing authorization request. Start the connection from your MCP client again.';
      loading = false;
      return;
    }
    try {
      const info = await api.txn(txnId);
      txn = info;
      username = info.username;
    } catch (e) {
      error =
        e.status === 404
          ? 'This authorization request is unknown or has expired. Start the connection from your MCP client again.'
          : e.message;
    } finally {
      loading = false;
    }
  }

  async function decide(approve) {
    busy = true;
    error = '';
    try {
      const result = await api.consent(txnId, approve);
      window.location.href = result.redirect_to;
    } catch (e) {
      error = e.message;
      busy = false;
    }
  }

  const clientLabel = $derived(txn?.client_name || txn?.client_id || '');
  const isCimdClient = $derived((txn?.client_id || '').startsWith('https://'));
</script>

<div class="card">
  {#if loading}
    <div class="spinner">Loading…</div>
  {:else if !txn}
    <h1>Authorization request</h1>
    <div class="error">{error}</div>
  {:else if !username}
    <h1>Sign in to MCP Gateway</h1>
    <p class="subtitle">
      <strong>{clientLabel}</strong> is requesting access to your MCP gateway.
    </p>
    <Login onLogin={(name) => (username = name)} />
  {:else}
    <h1>Authorize access</h1>
    <p class="subtitle">Signed in as <strong>{username}</strong></p>

    <p>
      <strong>{clientLabel}</strong> wants to connect to your MCP gateway and use the tools of
      all configured backends on your behalf.
    </p>

    <div class="kv">
      <div>
        <span class="k">Client</span>
        <span class="v">
          {clientLabel}
          {#if isCimdClient}<span class="badge ok">verified domain</span>{/if}
        </span>
      </div>
      {#if isCimdClient && txn.client_name}
        <div><span class="k">Client ID</span><span class="v">{txn.client_id}</span></div>
      {/if}
      <div><span class="k">Redirects to</span><span class="v">{txn.redirect_uri}</span></div>
      {#if txn.scopes?.length}
        <div><span class="k">Scopes</span><span class="v">{txn.scopes.join(' ')}</span></div>
      {/if}
    </div>

    {#if txn.is_loopback_redirect}
      <div class="warning">
        This request redirects to a local application on your computer
        (<code>{txn.redirect_host}</code>). Only approve if you just initiated this connection
        yourself (e.g. from Claude Code).
      </div>
    {/if}

    {#if error}
      <div class="error">{error}</div>
    {/if}

    <div class="row" style="margin-top: 1.4rem">
      <button class="secondary" onclick={() => decide(false)} disabled={busy}>Deny</button>
      <button class="primary" style="margin-top: 0" onclick={() => decide(true)} disabled={busy}>
        {busy ? 'Working…' : 'Approve'}
      </button>
    </div>
  {/if}
</div>
