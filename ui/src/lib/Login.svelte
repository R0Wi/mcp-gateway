<script>
  import { api } from './api.js';

  let { onLogin } = $props();

  let username = $state('');
  let password = $state('');
  // Until /auth/api/login-methods answers we don't know whether this gateway
  // has local users, an identity provider, or both -- render nothing rather
  // than flashing a password form that may not apply.
  let methods = $state(null);
  // A failed SSO round-trip comes back as ?oidc_error=... on whatever page
  // started it (see web.py::_oidc_failure), so surface it here where the
  // sign-in buttons are. Strip it from the address bar straight away: a
  // reload shouldn't replay a stale message, and it must not be carried
  // into the `next` URL of the retry.
  const params = new URLSearchParams(window.location.search);
  let error = $state(params.get('oidc_error') || '');
  let busy = $state(false);

  if (params.has('oidc_error')) {
    params.delete('oidc_error');
    const rest = params.toString();
    window.history.replaceState(null, '', window.location.pathname + (rest ? `?${rest}` : ''));
  }

  // Come back to the page the user is on -- including ?txn=... when this is
  // the consent screen, so the pending authorization survives the detour.
  const nextUrl = window.location.pathname + window.location.search;

  $effect(() => {
    loadMethods();
  });

  async function loadMethods() {
    try {
      methods = await api.loginMethods();
    } catch (e) {
      error = e.message;
      methods = { password: true, oidc: null };
    }
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

  function ssoLogin() {
    busy = true;
    // A real navigation, not a fetch: the provider's login page has to be
    // shown in this tab, and the flow cookie must be set along the way.
    window.location.href = `${methods.oidc.start_url}?next=${encodeURIComponent(nextUrl)}`;
  }
</script>

{#if methods}
  {#if error}
    <div class="error">{error}</div>
  {/if}

  {#if methods.password}
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
  {/if}

  {#if methods.oidc}
    {#if methods.password}
      <div class="separator"><span>or</span></div>
    {/if}
    <button
      class={methods.password ? 'secondary sso' : 'primary'}
      type="button"
      disabled={busy}
      onclick={ssoLogin}
    >
      Continue with {methods.oidc.name}
    </button>
  {/if}
{/if}
