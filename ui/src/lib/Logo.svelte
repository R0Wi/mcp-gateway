<script>
  let { size = 32 } = $props();
</script>

<svg
  width={size}
  height={(size * 240) / 360}
  viewBox="0 0 360 240"
  role="img"
  aria-label="MCP Gateway"
>
  <circle cx="26" cy="156" r="13" fill="var(--logo-primary)" />
  <line
    x1="39"
    y1="156"
    x2="110"
    y2="156"
    stroke="var(--logo-primary)"
    stroke-width="12"
    stroke-linecap="round"
  />
  <path
    d="M 118 200 L 118 108 A 58 58 0 0 1 234 108 L 234 200"
    fill="none"
    stroke="var(--logo-primary)"
    stroke-width="20"
    stroke-linecap="round"
  />
  <path
    d="M 166 86 Q 171.2 106.8 192 112 Q 171.2 117.2 166 138 Q 160.8 117.2 140 112 Q 160.8 106.8 166 86 Z"
    fill="var(--logo-primary)"
  />
  <path
    d="M 204 77 Q 206.2 85.8 215 88 Q 206.2 90.2 204 99 Q 201.8 90.2 193 88 Q 201.8 85.8 204 77 Z"
    fill="var(--logo-accent)"
  />
  <text
    x="176"
    y="188"
    text-anchor="middle"
    font-family="'IBM Plex Sans', sans-serif"
    font-weight="700"
    font-size="38"
    letter-spacing="0.5"
    fill="var(--logo-primary)">MCP</text
  >
  <path
    d="M 244 156 H 271 A 18 18 0 0 0 289 138 V 114 A 18 18 0 0 1 307 96 H 316"
    fill="none"
    stroke="var(--logo-accent)"
    stroke-width="12"
    stroke-linecap="round"
  />
  <path
    d="M 244 156 H 316"
    fill="none"
    stroke="var(--logo-accent)"
    stroke-width="12"
    stroke-linecap="round"
  />
  <path
    d="M 244 156 H 271 A 18 18 0 0 1 289 174 V 198 A 18 18 0 0 0 307 216 H 316"
    fill="none"
    stroke="var(--logo-accent)"
    stroke-width="12"
    stroke-linecap="round"
  />
  <circle cx="330" cy="96" r="13" fill="var(--logo-accent)" />
  <circle cx="330" cy="156" r="13" fill="var(--logo-accent)" />
  <circle cx="330" cy="216" r="13" fill="var(--logo-accent)" />
</svg>
