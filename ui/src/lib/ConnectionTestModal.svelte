<script>
  import { api } from './api.js';

  let { name, onclose } = $props();

  const CHECKS = [
    { key: 'ping', label: 'Ping MCP upstream' },
    { key: 'auth', label: 'Check tokens / auth' },
    { key: 'list_tools', label: 'List tools' },
  ];

  let results = $state(Object.fromEntries(CHECKS.map((c) => [c.key, { status: 'pending' }])));
  let error = $state('');
  let done = $state(false);

  const controller = new AbortController();

  $effect(() => {
    run();
    // Aborting on teardown covers the modal being dismissed by any path
    // other than the Cancel button (e.g. a future Escape/backdrop handler).
    return () => controller.abort();
  });

  async function run() {
    try {
      for await (const event of api.testConnection(name, controller.signal)) {
        results[event.check] = { status: event.status, detail: event.detail };
      }
    } catch (e) {
      if (e.name !== 'AbortError') {
        error = e.message;
      }
    } finally {
      done = true;
    }
  }

  function cancel() {
    controller.abort();
    onclose();
  }
</script>

<div class="backdrop">
  <div class="modal card">
    <h2>Test connection: {name}</h2>

    <ul class="checks">
      {#each CHECKS as c (c.key)}
        {@const r = results[c.key]}
        <li class="check {r.status}">
          <div class="check-row">
            <span class="icon">
              {#if r.status === 'ok'}
                &#10003;
              {:else if r.status === 'error'}
                &#10007;
              {:else if r.status === 'running'}
                <span class="spinner-icon"></span>
              {:else}
                &middot;
              {/if}
            </span>
            <span class="label">{c.label}</span>
          </div>
          {#if r.detail}
            <div class="detail">{r.detail}</div>
          {/if}
        </li>
      {/each}
    </ul>

    {#if error}
      <p class="error">{error}</p>
    {/if}

    <div class="actions">
      {#if done}
        <button class="primary" onclick={onclose}>Close</button>
      {:else}
        <button class="secondary" onclick={cancel}>Cancel</button>
      {/if}
    </div>
  </div>
</div>

<style>
  .backdrop {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.45);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 100;
    padding: 1rem;
  }

  .modal {
    width: 100%;
    max-width: 420px;
  }

  .modal h2 {
    font-size: 1.05rem;
    margin: 0 0 1rem;
  }

  .checks {
    list-style: none;
    margin: 0;
    padding: 0;
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
  }

  .check {
    padding: 0.6rem 0.8rem;
    font-size: 0.88rem;
    border-bottom: 1px solid var(--border);
  }

  .check:last-child {
    border-bottom: none;
  }

  .check-row {
    display: flex;
    align-items: baseline;
    gap: 0.6rem;
  }

  .icon {
    width: 1.1em;
    flex-shrink: 0;
    text-align: center;
    color: var(--muted);
  }

  .check.ok .icon {
    color: var(--ok);
  }

  .check.error .icon {
    color: var(--danger);
  }

  .check.error .label {
    color: var(--danger);
  }

  .detail {
    color: var(--muted);
    font-size: 0.8rem;
    margin: 0.2rem 0 0 1.7rem;
    word-break: break-word;
  }

  .actions {
    display: flex;
    justify-content: flex-end;
    margin-top: 1.25rem;
  }

  .actions button {
    width: auto;
    margin-top: 0;
  }
</style>
