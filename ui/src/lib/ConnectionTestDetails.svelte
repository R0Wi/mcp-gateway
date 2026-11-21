<script>
  // Full failure report for one connection-test check: the HTTP exchanges the
  // gateway saw, the exception chain and a best-guess hint. Opened on top of
  // the connection test modal so its step overview stays a one-liner per check.
  let { label, summary, details, onclose } = $props();

  let copied = $state(false);

  const AUTH_LABELS = {
    none: 'None',
    bearer: 'Static bearer token',
    headers: 'Static headers',
    oauth: 'OAuth',
  };

  function statusClass(status) {
    if (status >= 400) return 'bad';
    if (status >= 300) return 'redirect';
    return 'good';
  }

  function asText() {
    const lines = [
      `Check: ${label}`,
      `Result: ${summary}`,
      `Backend URL: ${details.backend_url}`,
      `Auth: ${AUTH_LABELS[details.auth_type] ?? details.auth_type}`,
    ];
    if (details.hint) lines.push(`Hint: ${details.hint}`);
    lines.push('', 'HTTP exchanges:');
    if (details.http.length === 0) lines.push('  (no HTTP response received)');
    for (const h of details.http) {
      lines.push(`  ${h.method} ${h.url} -> ${h.status} ${h.reason}`.trimEnd());
      for (const [k, v] of Object.entries(h.headers)) lines.push(`    ${k}: ${v}`);
      if (h.body) lines.push(...h.body.split('\n').map((l) => `    | ${l}`));
    }
    lines.push('', 'Exceptions:', ...details.exceptions.map((e) => `  ${e}`));
    return lines.join('\n');
  }

  async function copy() {
    try {
      await navigator.clipboard.writeText(asText());
      copied = true;
      setTimeout(() => (copied = false), 1500);
    } catch {
      /* clipboard unavailable (e.g. plain-http origin) -- nothing to do */
    }
  }

  function onkeydown(e) {
    if (e.key === 'Escape') {
      // Only close this layer, not the connection test modal underneath.
      e.stopPropagation();
      onclose();
    }
  }
</script>

<svelte:window {onkeydown} />

<div class="backdrop">
  <div class="modal card" role="dialog" aria-modal="true" aria-labelledby="details-title">
    <h2 id="details-title">Failure details: {label}</h2>

    <div class="body">
      {#if details.hint}
        <p class="hint">{details.hint}</p>
      {/if}

      <dl class="facts">
        <dt>Backend URL</dt>
        <dd class="mono">{details.backend_url}</dd>
        <dt>Auth</dt>
        <dd>{AUTH_LABELS[details.auth_type] ?? details.auth_type}</dd>
        <dt>Error</dt>
        <dd class="mono">{details.error}</dd>
      </dl>

      <h3>HTTP exchanges</h3>
      {#if details.http.length === 0}
        <p class="muted">No HTTP response was received from the backend.</p>
      {:else}
        <ol class="exchanges">
          {#each details.http as h, i (i)}
            <li>
              <div class="request">
                <span class="status {statusClass(h.status)}">{h.status}</span>
                <span class="mono">{h.method} {h.url}</span>
                {#if h.reason}<span class="muted">{h.reason}</span>{/if}
              </div>
              {#if Object.keys(h.headers).length}
                <dl class="headers mono">
                  {#each Object.entries(h.headers) as [k, v] (k)}
                    <dt>{k}:</dt>
                    <dd>{v}</dd>
                  {/each}
                </dl>
              {/if}
              {#if h.body}
                <pre>{h.body}</pre>
              {/if}
            </li>
          {/each}
        </ol>
      {/if}

      {#if details.exceptions.length > 1}
        <h3>Exception chain</h3>
        <ol class="exceptions mono">
          {#each details.exceptions as e, i (i)}
            <li>{e}</li>
          {/each}
        </ol>
      {/if}
    </div>

    <div class="actions">
      <button class="secondary small" onclick={copy}>{copied ? 'Copied' : 'Copy report'}</button>
      <button class="primary" onclick={onclose}>Back</button>
    </div>
  </div>
</div>

<style>
  .backdrop {
    position: fixed;
    inset: 0;
    background: rgba(0, 0, 0, 0.35);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 110;
    padding: 1rem;
  }

  .modal {
    width: 100%;
    max-width: 640px;
    max-height: calc(100vh - 2rem);
    display: flex;
    flex-direction: column;
  }

  .modal h2 {
    font-size: 1.05rem;
    margin: 0 0 1rem;
  }

  .body {
    overflow-y: auto;
    min-height: 0;
    font-size: 0.85rem;
  }

  h3 {
    font-size: 0.8rem;
    font-weight: 600;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.03em;
    margin: 1.1rem 0 0.5rem;
  }

  .mono {
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
    font-size: 0.8rem;
    overflow-wrap: anywhere;
  }

  .muted {
    color: var(--muted);
  }

  .hint {
    background: var(--warn-bg);
    color: var(--warn-text);
    border-radius: 8px;
    padding: 0.6rem 0.8rem;
    margin: 0 0 1rem;
  }

  .facts {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 0.35rem 1rem;
    margin: 0;
  }

  .facts dt {
    color: var(--muted);
  }

  .facts dd {
    margin: 0;
    min-width: 0;
  }

  .exchanges,
  .exceptions {
    margin: 0;
    padding: 0;
    list-style: none;
  }

  .exchanges li {
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.55rem 0.7rem;
    margin-bottom: 0.5rem;
  }

  .request {
    display: flex;
    align-items: baseline;
    flex-wrap: wrap;
    gap: 0.5rem;
  }

  .status {
    font-weight: 700;
    font-size: 0.75rem;
    border-radius: 4px;
    padding: 0.05rem 0.35rem;
  }

  .status.bad {
    color: var(--danger);
    background: color-mix(in srgb, var(--danger) 14%, transparent);
  }

  .status.redirect {
    color: var(--muted);
    background: color-mix(in srgb, var(--muted) 14%, transparent);
  }

  .status.good {
    color: var(--ok);
    background: color-mix(in srgb, var(--ok) 14%, transparent);
  }

  .headers {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 0.1rem 0.5rem;
    margin: 0.45rem 0 0;
    color: var(--muted);
  }

  .headers dd {
    margin: 0;
    min-width: 0;
    color: var(--text);
  }

  pre {
    margin: 0.45rem 0 0;
    padding: 0.5rem 0.6rem;
    background: var(--bg);
    border-radius: 6px;
    font-size: 0.78rem;
    white-space: pre-wrap;
    word-break: break-all;
    max-height: 14rem;
    overflow-y: auto;
  }

  .exceptions li {
    padding: 0.2rem 0;
  }

  .exceptions li + li::before {
    content: '↳ ';
    color: var(--muted);
  }

  .actions {
    display: flex;
    justify-content: flex-end;
    align-items: center;
    gap: 0.6rem;
    margin-top: 1.25rem;
  }

  .actions button {
    width: auto;
    margin-top: 0;
  }
</style>
