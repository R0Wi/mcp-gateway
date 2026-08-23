<script>
  import Authorize from './pages/Authorize.svelte';
  import Backends from './pages/Backends.svelte';

  // Tiny path-based router: the FastAPI server serves this SPA for any /ui/* path.
  const path = window.location.pathname.replace(/\/+$/, '');
  const page = path.endsWith('/authorize') ? 'authorize' : 'backends';
</script>

{#if page === 'authorize'}
  <Authorize />
{:else}
  <Backends />
{/if}
