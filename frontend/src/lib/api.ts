/**
 * CloudScan API Client with Server-Sent Events for real-time scan streaming.
 */

const API_BASE = '/api/v1';

interface RequestOptions extends RequestInit {
  params?: Record<string, string | number | undefined>;
}

class ApiClient {
  private token: string | null = null;
  private apiKey: string | null = null;

  setToken(token: string) { this.token = token; }
  setApiKey(key: string) { this.apiKey = key; }
  clearAuth() { this.token = null; this.apiKey = null; }

  private getHeaders(): Record<string, string> {
    const h: Record<string, string> = { 'Content-Type': 'application/json' };
    if (this.token) h['Authorization'] = `Bearer ${this.token}`;
    else if (this.apiKey) h['X-API-Key'] = this.apiKey;
    return h;
  }

  async request<T = any>(endpoint: string, options: RequestOptions = {}): Promise<T> {
    const { params, ...fetchOptions } = options;

    let url = `${API_BASE}${endpoint}`;
    if (params) {
      const qs = new URLSearchParams();
      Object.entries(params).forEach(([k, v]) => {
        if (v !== undefined && v !== '') qs.set(k, String(v));
      });
      const qsStr = qs.toString();
      if (qsStr) url += `?${qsStr}`;
    }

    const res = await fetch(url, {
      ...fetchOptions,
      headers: { ...this.getHeaders(), ...fetchOptions.headers as Record<string, string> },
    });

    if (!res.ok) {
      const body = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
      throw new ApiError(res.status, body.error || `HTTP ${res.status}`);
    }

    return res.json();
  }

  // ── Auth ──
  register(email: string, username: string, password: string) {
    return this.request('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, username, password }),
    });
  }

  login(email: string, password: string) {
    return this.request('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
  }

  getMe() { return this.request('/auth/me'); }

  // ── Search ──
  searchFiles(params: {
    q?: string; ext?: string; exclude_ext?: string;
    provider?: string; bucket?: string; sort?: string;
    page?: number; per_page?: number;
    min_size?: number; max_size?: number;
  }) {
    return this.request('/files', { params: params as any });
  }

  getRandomFiles(count = 20) {
    return this.request('/files/random', { params: { count } });
  }

  // ── Buckets ──
  listBuckets(params: {
    provider?: string; status?: string; search?: string;
    page?: number; per_page?: number;
  } = {}) {
    return this.request('/buckets', { params: params as any });
  }

  getBucket(id: number, page = 1, per_page = 100) {
    return this.request(`/buckets/${id}`, { params: { page, per_page } });
  }

  // ── Stats ──
  getStats() { return this.request('/stats'); }

  // ── Providers ──
  getProviders() { return this.request('/providers'); }

  // ── Scans ──
  createScan(config: {
    keywords?: string[]; companies?: string[];
    providers?: string[]; max_names?: number;
  }) {
    return this.request('/scans', {
      method: 'POST',
      body: JSON.stringify(config),
    });
  }

  getScan(jobId: number) { return this.request(`/scans/${jobId}`); }
  listScans() { return this.request('/scans'); }

  cancelScan(jobId: number) {
    return this.request(`/scans/${jobId}/cancel`, { method: 'POST' });
  }

  // ── SSE: Real-time scan events ──
  subscribeScanEvents(handlers: {
    onProgress?: (data: any) => void;
    onBucketFound?: (data: any) => void;
    onScanComplete?: (data: any) => void;
    onScanStarted?: (data: any) => void;
    onError?: (data: any) => void;
    onConnect?: () => void;
    onDisconnect?: () => void;
  }): () => void {
    const es = new EventSource(`${API_BASE}/events/scans`);

    es.addEventListener('connected', () => handlers.onConnect?.());
    es.addEventListener('progress', (e) => handlers.onProgress?.(JSON.parse(e.data)));
    es.addEventListener('bucket_found', (e) => handlers.onBucketFound?.(JSON.parse(e.data)));
    es.addEventListener('scan_complete', (e) => handlers.onScanComplete?.(JSON.parse(e.data)));
    es.addEventListener('scan_started', (e) => handlers.onScanStarted?.(JSON.parse(e.data)));
    es.addEventListener('error', (e) => {
      if (e instanceof MessageEvent) handlers.onError?.(JSON.parse(e.data));
      else handlers.onDisconnect?.();
    });

    es.onerror = () => handlers.onDisconnect?.();

    // Return cleanup function
    return () => es.close();
  }
}

class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = 'ApiError';
  }
}

export const api = new ApiClient();
export { ApiError };
