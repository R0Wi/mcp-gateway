<script>
  import { api } from './api.js';

  let { onLogin } = $props();

  let username = $state('');
  let password = $state('');
  let error = $state('');
  let busy = $state(false);

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

  {#if error}
    <div class="error">{error}</div>
  {/if}

  <button class="primary" type="submit" disabled={busy}>
    {busy ? 'Signing in…' : 'Sign in'}
  </button>
</form>
