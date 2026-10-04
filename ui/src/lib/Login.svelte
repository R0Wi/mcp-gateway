<script>
  import { api } from './api.js';

  let { onLogin } = $props();

  let username = $state('');
  let password = $state('');
  let error = $state('');
  let busy = $state(false);
  // null until /auth/api/login-options answers: which sign-in methods to offer.
  let options = $state(null);

  // An external (OIDC) sign-in ends with a full-page redirect back here;
  // failures arrive as ?login_error=. Show it once, then drop it from the URL
  // so a reload doesn't replay it -- and so it isn't carried into return_to.
  const params = new URLSearchParams(window.location.search);
  if (params.has('login_error')) {
    error = params.get('login_error');
    params.delete('login_error');
    const rest = params.toString();
    window.history.replaceState(null, '', `${window.location.pathname}${rest ? `?${rest}` : ''}`);
  }

  $effect(() => {
    api
      .loginOptions()
      .then((o) => (options = o))
      .catch(() => (options = { password: true, providers: [] }));
  });

  function providerHref(name) {
    const returnTo = `${window.location.pathname}${window.location.search}`;
    return `/auth/oidc/${encodeURIComponent(name)}/login?return_to=${encodeURIComponent(returnTo)}`;
  }

  async function submit(event) {
    event.preventDefault();
    error = '';
    busy = true;
    try {
      const result = await api.login(username, password);
      onLogin(result.username);
    } catch (e) {
      error = e.message;
    } finally {
      busy = false;
    }
  }
</script>

{#if options}
  {#if options.providers.length}
    <div class="providers">
      {#each options.providers as p (p.name)}
        <a class="sso" href={providerHref(p.name)}>
          {#if p.type === 'entra'}
            <svg width="18" height="18" viewBox="0 0 21 21" aria-hidden="true">
              <rect x="1" y="1" width="9" height="9" fill="#f25022" />
              <rect x="11" y="1" width="9" height="9" fill="#7fba00" />
              <rect x="1" y="11" width="9" height="9" fill="#00a4ef" />
              <rect x="11" y="11" width="9" height="9" fill="#ffb900" />
            </svg>
          {:else}
            <svg width="18" height="18" viewBox="0 0 24 24" aria-hidden="true" fill="none"
              stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
              <circle cx="7.5" cy="15.5" r="4.5" />
              <path d="m10.7 12.3 9.8-9.8M17 6l3 3M14.5 8.5l2 2" />
            </svg>
          {/if}
          Sign in with {p.display_name}
        </a>
      {/each}
    </div>
  {/if}

  {#if options.password && options.providers.length}
    <div class="divider"><span>or</span></div>
  {/if}

  {#if options.password}
    <form onsubmit={submit}>
      <label for="username">Username</label>
      <input id="username" bind:value={username} autocomplete="username" required />

      <label for="password">Password</label>
      <input
        id="password"
        type="password"
        bind:value={password}
        autocomplete="current-password"
        required
      />

      <button class="primary" type="submit" disabled={busy}>
        {busy ? 'Signing in…' : 'Sign in'}
      </button>
    </form>
  {:else if !options.providers.length}
    <p class="muted">No sign-in method is configured for this gateway.</p>
  {/if}
{/if}

{#if error}
  <div class="error">{error}</div>
{/if}

<style>
  .providers {
    display: flex;
    flex-direction: column;
    gap: 0.6rem;
  }

  .sso {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0.6rem;
    padding: 0.6rem 1.1rem;
    border: 1px solid var(--border);
    border-radius: 8px;
    color: var(--text);
    font-weight: 600;
    text-decoration: none;
    background: var(--card);
  }

  .sso:hover {
    border-color: var(--accent);
  }

  .divider {
    display: flex;
    align-items: center;
    gap: 0.75rem;
    margin: 1.2rem 0 0.2rem;
    color: var(--muted);
    font-size: 0.8rem;
  }

  .divider::before,
  .divider::after {
    content: '';
    flex: 1;
    border-top: 1px solid var(--border);
  }
</style>
