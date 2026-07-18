const API_BASE = import.meta.env.VITE_API_BASE_URL || "http://localhost:8000";

async function request(path, options = {}) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail || `Request failed: ${res.status}`);
  }
  return res.json();
}

export function triggerScan(payload) {
  return request("/api/scan", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export function getScan(scanId) {
  return request(`/api/scan/${scanId}`);
}

export function reportUrl(scanId) {
  return `${API_BASE}/api/scan/${scanId}/report`;
}
