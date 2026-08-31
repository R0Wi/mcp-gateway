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
};
