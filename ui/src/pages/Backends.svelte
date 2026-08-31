<script>
  import { api } from '../lib/api.js';
  import Login from '../lib/Login.svelte';
  import Logo from '../lib/Logo.svelte';
  import Banner from '../lib/Banner.svelte';
  import ConnectionTestModal from '../lib/ConnectionTestModal.svelte';

  const params = new URLSearchParams(window.location.search);

  let username = $state(null);
  let backends = $state([]);
  let loading = $state(true);
  // Name of the backend currently starting a connect flow, if any -- greys
  // out and spins that one button while we wait on /oauth/connect. Cleared
  // on failure; left set on success since the page navigates away anyway.
  let connecting = $state(null);
  // Name of the backend whose connection-test modal is open, if any.
  let testing = $state(null);
  let error = $state(params.get('error') || '');
  let notice = $state(
    params.get('connected') ? `Backend "${params.get('connected')}" connected successfully.` : ''
  );

  // The error/connected params only ever come from the one-shot redirect
  // the backend issues from /oauth/callback (the browser returning from the
  // upstream authorization server, which can't be a fetch); once shown, drop
  // them so a reload or share of the URL doesn't replay a stale banner.
  if (params.has('error') || params.has('connected')) {
    params.delete('error');
    params.delete('connected');
    const rest = params.toString();
    window.history.replaceState(null, '', `/ui/backends${rest ? `?${rest}` : ''}`);
  }

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
        await connect(next.slice(8));
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

  async function connect(name) {
    error = '';
    connecting = name;
    try {
      const { authorize_url } = await api.connect(name);
      // Success leaves the page via a real navigation to the upstream
      // authorization server; failure stays put and shows a dismissible
      // banner instead of round-tripping through a server redirect.
      window.location.href = authorize_url;
    } catch (e) {
      connecting = null;
      if (e.status === 401) {
        window.location.href = `/ui/backends?login_next=connect:${encodeURIComponent(name)}`;
        return;
      }
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
    <div class="login-header">
      <div>
        <h1>MCP Gateway</h1>
        <p class="subtitle">Sign in to manage backend connections.</p>
      </div>
      <Logo size={76} />
    </div>
    <Login {onLogin} />
  {:else}
    <div class="topbar">
      <div class="brand">
        <Logo size={28} />
        <h1>Backends</h1>
      </div>
      <button class="secondary small" onclick={logout}>Sign out ({username})</button>
    </div>
    <p class="subtitle">
      Upstream MCP servers aggregated by this gateway. OAuth backends must be connected once.
    </p>

    {#if notice}
      <Banner kind="notice" onclose={() => (notice = '')}>{notice}</Banner>
    {/if}
    {#if error}
      <Banner kind="error" onclose={() => (error = '')}>{error}</Banner>
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
          {#if b.enabled}
            <div class="row">
              {#if b.auth_type === 'oauth'}
                {#if b.connected}
                  <button
                    class="secondary small"
                    disabled={connecting === b.name}
                    onclick={() => disconnect(b.name)}
                  >
                    Disconnect
                  </button>
                  <button
                    class="secondary small"
                    disabled={connecting === b.name}
                    onclick={() => connect(b.name)}
                  >
                    {#if connecting === b.name}<span class="spinner-icon"></span>Reconnecting…{:else}Reconnect{/if}
                  </button>
                {:else}
                  <button
                    class="primary small"
                    style="margin-top: 0; width: auto"
                    disabled={connecting === b.name}
                    onclick={() => connect(b.name)}
                  >
                    {#if connecting === b.name}<span class="spinner-icon"></span>Connecting…{:else}Connect{/if}
                  </button>
                {/if}
              {/if}
              <button class="secondary small" onclick={() => (testing = b.name)}>
                Test connection
              </button>
            </div>
          {/if}
        </div>
      {/each}
    </div>

    {#if testing}
      <ConnectionTestModal name={testing} onclose={() => (testing = null)} />
    {/if}
  {/if}
</div>
