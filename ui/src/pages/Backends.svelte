<script>
  import { api } from '../lib/api.js';
  import Login from '../lib/Login.svelte';

  const params = new URLSearchParams(window.location.search);

  let username = $state(null);
  let backends = $state([]);
  let loading = $state(true);
  let error = $state(params.get('error') || '');
  let notice = $state(
    params.get('connected') ? `Backend "${params.get('connected')}" connected successfully.` : ''
  );

  $effect(() => {
    init();
  });

  async function init() {
    try {
      const me = await api.me();
      username = me.username;
      if (username) {
        await refresh();
      }
    } catch (e) {
      error = e.message;
    } finally {
      loading = false;
    }
  }

  async function refresh() {
    backends = await api.backends();
  }

  async function onLogin(name) {
    username = name;
    loading = true;
    try {
      await refresh();
      const next = params.get('login_next');
      if (next?.startsWith('connect:')) {
        window.location.href = `/oauth/connect/${encodeURIComponent(next.slice(8))}`;
        return;
      }
    } catch (e) {
      error = e.message;
    } finally {
      loading = false;
    }
  }

  async function disconnect(name) {
    if (!confirm(`Remove stored credentials for "${name}"?`)) return;
    error = '';
    try {
      await api.disconnect(name);
      await refresh();
    } catch (e) {
      error = e.message;
    }
  }

  async function logout() {
    await api.logout();
    username = null;
    backends = [];
  }

  function authLabel(b) {
    if (b.auth_type === 'oauth') return b.registration ? `oauth (${b.registration})` : 'oauth';
    return b.auth_type;
  }
</script>

<div class="card wide">
  {#if loading}
    <div class="spinner">Loading…</div>
  {:else if !username}
    <h1>MCP Gateway</h1>
    <p class="subtitle">Sign in to manage backend connections.</p>
    <Login {onLogin} />
  {:else}
    <div class="topbar">
      <h1>Backends</h1>
      <button class="secondary small" onclick={logout}>Sign out ({username})</button>
    </div>
    <p class="subtitle">
      Upstream MCP servers aggregated by this gateway. OAuth backends must be connected once.
    </p>

    {#if notice}
      <div class="notice">{notice}</div>
    {/if}
    {#if error}
      <div class="error">{error}</div>
    {/if}

    {#if backends.length === 0}
      <p class="muted">No backends configured. Add them to the gateway config file.</p>
    {/if}

    <div>
      {#each backends as b (b.name)}
        <div class="backend">
          <div class="info">
            <div class="name">
              {b.name}
              <span class="badge plain">{authLabel(b)}</span>
              {#if !b.enabled}
                <span class="badge plain">disabled</span>
              {:else if b.connected}
                <span class="badge ok">connected</span>
              {:else}
                <span class="badge pending">not connected</span>
              {/if}
            </div>
            <div class="url">{b.url}</div>
          </div>
          {#if b.auth_type === 'oauth' && b.enabled}
            <div class="row">
              {#if b.connected}
                <button class="secondary small" onclick={() => disconnect(b.name)}>
                  Disconnect
                </button>
                <a href={`/oauth/connect/${encodeURIComponent(b.name)}`}>
                  <button class="secondary small">Reconnect</button>
                </a>
              {:else}
                <a href={`/oauth/connect/${encodeURIComponent(b.name)}`}>
                  <button class="primary small" style="margin-top: 0; width: auto">Connect</button>
                </a>
              {/if}
            </div>
          {/if}
        </div>
      {/each}
    </div>
  {/if}
</div>
