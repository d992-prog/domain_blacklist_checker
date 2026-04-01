export type SourceResult = {
  source: string;
  listed: boolean;
  reason: string | null;
  listed_since: string | null;
  category: string | null;
  severity: string | null;
};

export type LumenNotice = {
  title: string;
  notice_type: string;
  sender: string | null;
  date: string | null;
  description: string | null;
};

export type DomainReport = {
  domain: string;
  overall_status: "clean" | "warning" | "listed";
  risk_score: number;
  blacklists: SourceResult[];
  lumen: {
    status: "ok" | "unknown";
    total_notices: number;
    trend: string | null;
    notices: LumenNotice[];
    note: string | null;
  };
  safe_browsing: {
    status: "safe" | "malware" | "phishing" | "unwanted" | "unknown";
    note: string | null;
  };
  email_auth: {
    spf: "pass" | "fail" | "none";
    dkim: "pass" | "fail" | "none";
    dmarc: "pass" | "fail" | "none";
    note: string | null;
  };
  providers: Array<{
    name: string;
    status: string;
    listed: boolean | null;
    note: string | null;
  }>;
  recommendations: string[];
  checked_at: string;
};

export type JobResponse = {
  job_id: string;
  status: string;
  total_domains: number;
};

export type JobStatusResponse = {
  job_id: string;
  status: string;
  progress: number;
  total_domains: number;
  completed_domains: number;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  last_error: string | null;
  reports: DomainReport[];
};

export type HistoryItem = {
  job_id: string;
  domain: string;
  overall_status: string;
  risk_score: number;
  checked_at: string;
};

export type ProxyEndpoint = {
  id: number;
  scheme: string;
  host: string;
  port: number;
  username: string | null;
  password: string | null;
  is_active: boolean;
  fail_count: number;
  success_count: number;
  last_used_at: string | null;
  last_error: string | null;
  created_at: string;
  updated_at: string;
  display_url: string;
};

export type WebhookSubscription = {
  id: number;
  url: string;
  events: string[];
  created_at: string;
};

export type WatchlistItem = {
  id: number;
  domain: string;
  interval_hours: number;
  is_active: boolean;
  last_checked_at: string | null;
  next_check_at: string | null;
  last_job_id: string | null;
  last_status: string | null;
  last_risk_score: number | null;
  created_at: string;
  updated_at: string;
};

export type RuntimeSummary = {
  app_name: string;
  proxy_attempts_per_request: number;
  direct_http_fallback: boolean;
  max_parallel_jobs: number;
  check_rate_limit_per_minute: number;
  watch_scheduler_poll_seconds: number;
  configured_providers: {
    google_safe_browsing: boolean;
    lumen: boolean;
    virustotal: boolean;
    phishtank: boolean;
    abuseipdb: boolean;
    urlhaus: boolean;
    talos: boolean;
    webhook_signing: boolean;
  };
  active_proxies: number;
  active_watchlist: number;
  is_admin: boolean;
};

export type User = {
  id: number;
  username: string;
  role: string;
  status: string;
  language: "ru" | "en";
  max_domains: number | null;
  access_expires_at: string | null;
  status_message: string | null;
  last_login_at: string | null;
  deleted_at: string | null;
  created_at: string;
  updated_at: string;
};

export type SessionResponse = {
  user: User;
  has_feature_access: boolean;
};

export type AdminUser = {
  id: number;
  username: string;
  role: string;
  status: string;
  language: string;
  max_domains: number | null;
  access_expires_at: string | null;
  status_message: string | null;
  last_login_at: string | null;
  deleted_at: string | null;
  created_at: string;
  updated_at: string;
  job_count: number;
  proxy_count: number;
  watch_count: number;
};

export type ProviderSettings = {
  google_safe_browsing_api_key: string | null;
  lumen_search_url: string | null;
  virustotal_api_key: string | null;
  phishtank_app_key: string | null;
  phishtank_user_agent: string | null;
  abuseipdb_api_key: string | null;
  urlhaus_api_url: string | null;
  urlhaus_auth_key: string | null;
  talos_api_url: string | null;
  webhook_signing_secret: string | null;
  configured: Record<string, boolean>;
};

export type AdminOverview = {
  total_users: number;
  active_users: number;
  total_jobs: number;
  total_proxies: number;
  total_watchlist: number;
};

const API_BASE = import.meta.env.VITE_API_BASE ?? "/api";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, {
    credentials: "include",
    headers: {
      Accept: "application/json",
      ...(init?.body instanceof FormData ? {} : { "Content-Type": "application/json" }),
      ...(init?.headers ?? {}),
    },
    ...init,
  });

  if (!response.ok) {
    const contentType = response.headers.get("content-type") ?? "";
    if (contentType.includes("application/json")) {
      const payload = (await response.json()) as { detail?: string };
      throw new Error(payload.detail || `Request failed with ${response.status}`);
    }
    throw new Error((await response.text()) || `Request failed with ${response.status}`);
  }

  return (await response.json()) as T;
}

export const api = {
  register: (username: string, password: string, language: "ru" | "en") =>
    request<SessionResponse>("/auth/register", {
      method: "POST",
      body: JSON.stringify({ username, password, language }),
    }),
  login: (username: string, password: string, remember_me: boolean) =>
    request<SessionResponse>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ username, password, remember_me }),
    }),
  logout: () =>
    request<{ detail: string }>("/auth/logout", {
      method: "POST",
    }),
  getMe: () => request<SessionResponse>("/auth/me"),
  updateProfile: (language: "ru" | "en") =>
    request<SessionResponse>("/auth/profile", {
      method: "PATCH",
      body: JSON.stringify({ language }),
    }),
  changePassword: (current_password: string, new_password: string) =>
    request<SessionResponse>("/auth/change-password", {
      method: "POST",
      body: JSON.stringify({ current_password, new_password }),
    }),
  createCheck: (domains: string[]) =>
    request<JobResponse>("/check", {
      method: "POST",
      body: JSON.stringify({ domains }),
    }),
  createCheckFromFile: (file: File) => {
    const formData = new FormData();
    formData.append("file", file);
    return request<JobResponse>("/check/upload", {
      method: "POST",
      body: formData,
    });
  },
  getStatus: (jobId: string) => request<JobStatusResponse>(`/status/${jobId}`),
  getHistory: (domain = "", days = 30) =>
    request<HistoryItem[]>(
      `/history?${new URLSearchParams({
        ...(domain ? { domain } : {}),
        days: String(days),
      }).toString()}`,
    ),
  getProxies: () => request<ProxyEndpoint[]>("/proxies"),
  createProxy: (proxy_url: string) =>
    request<ProxyEndpoint>("/proxies", {
      method: "POST",
      body: JSON.stringify({ proxy_url }),
    }),
  updateProxy: (id: number, is_active: boolean) =>
    request<ProxyEndpoint>(`/proxies/${id}`, {
      method: "PATCH",
      body: JSON.stringify({ is_active }),
    }),
  deleteProxy: (id: number) =>
    request<{ detail: string }>(`/proxies/${id}`, {
      method: "DELETE",
    }),
  getWebhooks: () => request<WebhookSubscription[]>("/webhook"),
  createWebhook: (url: string, events: string[]) =>
    request<WebhookSubscription>("/webhook", {
      method: "POST",
      body: JSON.stringify({ url, events }),
    }),
  testWebhook: (id: number) =>
    request<{ detail: string }>(`/webhook/${id}/test`, {
      method: "POST",
    }),
  deleteWebhook: (id: number) =>
    request<{ detail: string }>(`/webhook/${id}`, {
      method: "DELETE",
    }),
  getWatchlist: () => request<WatchlistItem[]>("/watchlist"),
  createWatchlist: (domain: string, interval_hours: number) =>
    request<WatchlistItem>("/watchlist", {
      method: "POST",
      body: JSON.stringify({ domain, interval_hours }),
    }),
  updateWatchlist: (id: number, payload: { interval_hours?: number; is_active?: boolean }) =>
    request<WatchlistItem>(`/watchlist/${id}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    }),
  runWatchlistNow: (id: number) =>
    request<WatchlistItem>(`/watchlist/${id}/run`, {
      method: "POST",
    }),
  deleteWatchlist: (id: number) =>
    request<{ detail: string }>(`/watchlist/${id}`, {
      method: "DELETE",
    }),
  getRuntimeSummary: () => request<RuntimeSummary>("/health/runtime"),
  getAdminOverview: () => request<AdminOverview>("/admin/overview"),
  getAdminUsers: () => request<AdminUser[]>("/admin/users"),
  updateAdminUser: (id: number, payload: Partial<Pick<AdminUser, "status" | "role" | "language" | "max_domains" | "status_message">>) =>
    request<User>(`/admin/users/${id}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    }),
  getProviderSettings: () => request<ProviderSettings>("/admin/provider-settings"),
  updateProviderSettings: (payload: Omit<ProviderSettings, "configured">) =>
    request<ProviderSettings>("/admin/provider-settings", {
      method: "PUT",
      body: JSON.stringify(payload),
    }),
  streamStatusUrl: (jobId: string) => `${API_BASE}/status/${jobId}/stream`,
  reportUrl: (jobId: string, format: "json" | "csv" | "pdf") =>
    `${API_BASE}/report/${jobId}?format=${format}`,
};
