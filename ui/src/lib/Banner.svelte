<script>
  let { kind = 'error', children, onclose } = $props();
</script>

<div class="banner {kind}">
  <span class="text">{@render children()}</span>
  <button type="button" class="close" aria-label="Dismiss" onclick={onclose}>&times;</button>
</div>

<style>
  .banner {
    display: flex;
    align-items: flex-start;
    gap: 0.6rem;
    border-radius: 8px;
    padding: 0.6rem 0.6rem 0.6rem 0.8rem;
    font-size: 0.85rem;
    margin-top: 1rem;
  }

  .banner.error {
    background: color-mix(in srgb, var(--danger) 12%, transparent);
    color: var(--danger);
  }

  .banner.notice {
    background: color-mix(in srgb, var(--ok) 12%, transparent);
    color: var(--ok);
  }

  .text {
    flex: 1;
    word-break: break-word;
  }

  .close {
    background: transparent;
    border: none;
    color: inherit;
    cursor: pointer;
    font-size: 1.1rem;
    line-height: 1;
    padding: 0 0.15rem;
    opacity: 0.7;
  }

  .close:hover {
    opacity: 1;
  }
</style>
