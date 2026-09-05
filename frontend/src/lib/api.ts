function getCSRFToken(): string {
  const match = document.cookie.match(new RegExp('(^| )csrf_token=([^;]+)'));
  return match ? decodeURIComponent(match[2]) : '';
}

export async function apiRequest<T = any>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const headers = new Headers(options.headers || {});
  
  if (!headers.has('Content-Type') && !(options.body instanceof FormData)) {
    headers.set('Content-Type', 'application/json');
  }

  const method = (options.method || 'GET').toUpperCase();
  if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
    const csrf = getCSRFToken();
    if (csrf) {
      headers.set('X-CSRF-Token', csrf);
    }
  }

  const response = await fetch(endpoint, {
    ...options,
    headers,
    credentials: 'same-origin',
  });

  if (!response.ok) {
    let errorMsg = `HTTP Error ${response.status}`;
    try {
      const errData = await response.json();
      errorMsg = errData.message || errData.error || errorMsg;
    } catch {
      const text = await response.text();
      if (text) errorMsg = text;
    }
    throw new Error(errorMsg);
  }

  const contentType = response.headers.get('Content-Type') || '';
  if (contentType.includes('application/json')) {
    return response.json();
  }
  return response.text() as any;
}

export const getJSON = <T>(url: string) => apiRequest<T>(url, { method: 'GET' });
export const postJSON = <T>(url: string, body?: any) =>
  apiRequest<T>(url, { method: 'POST', body: body ? JSON.stringify(body) : undefined });
// postBlob downloads a file through a CSRF-protected POST and keeps the filename the
// server chose, so a capsule lands under its capsule ID rather than a generic name.
export async function postBlob(url: string, fallbackName: string): Promise<{ blob: Blob; filename: string }> {
  const headers = new Headers({ 'X-CSRF-Token': getCSRFToken() });
  const response = await fetch(url, { method: 'POST', headers, credentials: 'same-origin' });
  if (!response.ok) {
    let msg = `HTTP Error ${response.status}`;
    try {
      const errData = await response.json();
      msg = errData.message || errData.error || msg;
    } catch {
      // not JSON; keep the status
    }
    throw new Error(msg);
  }
  const match = /filename="([^"]+)"/.exec(response.headers.get('Content-Disposition') ?? '');
  return { blob: await response.blob(), filename: match ? match[1] : fallbackName };
}
export const putJSON = <T>(url: string, body?: any) =>
  apiRequest<T>(url, { method: 'PUT', body: body ? JSON.stringify(body) : undefined });
export const deleteJSON = <T>(url: string) => apiRequest<T>(url, { method: 'DELETE' });

export function toErrorMessage(err: unknown, fallback: string): string {
  if (err instanceof Error) return err.message;
  if (typeof err === 'string') return err;
  return fallback;
}
