async function request(path, options = {}) {
  const res = await fetch(path, {
    credentials: 'same-origin',
    headers: options.body ? { 'Content-Type': 'application/json' } : {},
    ...options,
  });
  let data = null;
  try {
    data = await res.json();
  } catch {
    /* non-JSON response */
  }
  if (!res.ok) {
    const detail = data?.detail || data?.error || `Request failed (${res.status})`;
    const err = new Error(detail);
    err.status = res.status;
    throw err;
  }
  return data;
}

export const api = {
  me: () => request('/auth/api/me'),
  loginMethods: () => request('/auth/api/login-methods'),
  txn: (id) => request(`/auth/api/txn/${encodeURIComponent(id)}`),
  login: (username, password) =>
    request('/auth/api/login', { method: 'POST', body: JSON.stringify({ username, password }) }),
  logout: () => request('/auth/api/logout', { method: 'POST' }),
  consent: (txn_id, approve) =>
    request('/auth/api/consent', { method: 'POST', body: JSON.stringify({ txn_id, approve }) }),
  backends: () => request('/auth/api/backends'),
  disconnect: (name) =>
    request(`/auth/api/backends/${encodeURIComponent(name)}/disconnect`, { method: 'POST' }),
  connect: (name) => request(`/oauth/connect/${encodeURIComponent(name)}`),

  // Streams newline-delimited JSON progress events ({ check, status, detail? })
  // as an async generator, so the caller can render each check live. Abort
  // `signal` to cancel the in-flight test.
  async *testConnection(name, signal) {
    const res = await fetch(`/auth/api/backends/${encodeURIComponent(name)}/test-connection`, {
      method: 'POST',
      credentials: 'same-origin',
      signal,
    });
    if (!res.ok) {
      let detail;
      try {
        detail = (await res.json())?.detail;
      } catch {
        /* non-JSON error response */
      }
      const err = new Error(detail || `Request failed (${res.status})`);
      err.status = res.status;
      throw err;
    }
    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';
    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        let newlineAt;
        while ((newlineAt = buffer.indexOf('\n')) >= 0) {
          const line = buffer.slice(0, newlineAt);
          buffer = buffer.slice(newlineAt + 1);
          if (line.trim()) yield JSON.parse(line);
        }
      }
      if (buffer.trim()) yield JSON.parse(buffer);
    } finally {
      reader.releaseLock();
    }
  },
};
