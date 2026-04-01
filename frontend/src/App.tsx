import { ChangeEvent, FormEvent, useEffect, useMemo, useState } from "react";

import {
  AdminOverview,
  AdminUser,
  api,
  DomainReport,
  HistoryItem,
  JobStatusResponse,
  ProviderSettings,
  ProxyEndpoint,
  RuntimeSummary,
  SessionResponse,
  WatchlistItem,
  WebhookSubscription,
} from "./api";

type Locale = "ru" | "en";
type Toast = { type: "success" | "error"; text: string } | null;
type TabKey = "history" | "watchlist" | "proxies" | "webhooks" | "admin";

const emptyProviderSettings: Omit<ProviderSettings, "configured"> = {
  google_safe_browsing_api_key: "",
  lumen_search_url: "",
  virustotal_api_key: "",
  phishtank_app_key: "",
  phishtank_user_agent: "domain-blacklist-checker/1.0",
  abuseipdb_api_key: "",
  urlhaus_api_url: "https://urlhaus-api.abuse.ch/v1/host/",
  urlhaus_auth_key: "",
  talos_api_url: "",
  webhook_signing_secret: "",
};

function t(locale: Locale, ru: string, en: string) {
  return locale === "ru" ? ru : en;
}

function parseDomains(input: string) {
  return input
    .split(/[\s,;]+/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function formatDate(locale: Locale, value: string | null) {
  if (!value) {
    return t(locale, "Нет данных", "No data");
  }
  return new Intl.DateTimeFormat(locale === "ru" ? "ru-RU" : "en-US", {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  }).format(new Date(value));
}

function scoreTone(score: number) {
  if (score >= 60) return "listed";
  if (score > 0) return "warning";
  return "clean";
}

function metricValue(reports: DomainReport[], mode: "listed" | "warning" | "clean") {
  return reports.filter((report) => report.overall_status === mode).length;
}

function averageRisk(reports: DomainReport[]) {
  if (!reports.length) return 0;
  return Math.round(reports.reduce((sum, report) => sum + report.risk_score, 0) / reports.length);
}

function findProvider(report: DomainReport, name: string) {
  return report.providers.find((provider) => provider.name === name) ?? null;
}

function providerStateLabel(locale: Locale, value: string | boolean | null | undefined) {
  if (value === true) return t(locale, "Да", "Yes");
  if (value === false) return t(locale, "Нет", "No");
  if (value === null || value === undefined || value === "") return t(locale, "Не настроено", "Not configured");
  return String(value);
}

function Hint({ text }: { text: string }) {
  return (
    <span className="hint" title={text} aria-label={text}>
      ?
    </span>
  );
}

function StatusBadge({ status, locale }: { status: string; locale: Locale }) {
  const labels: Record<string, string> = {
    clean: t(locale, "Чисто", "Clean"),
    warning: t(locale, "Риск", "Warning"),
    listed: t(locale, "В листинге", "Listed"),
    completed: t(locale, "Завершено", "Completed"),
    running: t(locale, "Идёт", "Running"),
    queued: t(locale, "В очереди", "Queued"),
    failed: t(locale, "Ошибка", "Failed"),
    approved: t(locale, "Активен", "Approved"),
    blocked: t(locale, "Заблокирован", "Blocked"),
    pending: t(locale, "Ожидает", "Pending"),
  };
  return <span className={`status ${status}`}>{labels[status] ?? status}</span>;
}

function AuthScreen({
  locale,
  onLogin,
  onRegister,
  authLoading,
}: {
  locale: Locale;
  onLogin: (username: string, password: string, remember: boolean) => Promise<void>;
  onRegister: (username: string, password: string) => Promise<void>;
  authLoading: boolean;
}) {
  const [mode, setMode] = useState<"login" | "register">("login");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [remember, setRemember] = useState(true);

  async function submit(event: FormEvent) {
    event.preventDefault();
    if (mode === "login") {
      await onLogin(username, password, remember);
      return;
    }
    await onRegister(username, password);
  }

  return (
    <div className="auth-shell">
      <section className="auth-card hero-card">
        <div className="auth-copy">
          <p className="eyebrow">{t(locale, "Личный кабинет и админка", "Private workspace and admin")}</p>
          <h1>Domain Blacklist Checker</h1>
          <p className="subtitle">
            {t(
              locale,
              "Регистрация, отдельные данные на пользователя, глобальные API-ключи в админке и короткие карточки результатов сверху.",
              "Registration, isolated user data, global API keys in admin, and compact result cards at the top.",
            )}
          </p>
          <div className="hero-meta">
            <span className="muted-chip">RU / EN</span>
            <span className="muted-chip">{t(locale, "Свои прокси", "Own proxies")}</span>
            <span className="muted-chip">{t(locale, "Своя история", "Own history")}</span>
          </div>
        </div>

        <form className="auth-form" onSubmit={(event) => void submit(event)}>
          <div className="auth-switch">
            <button type="button" className={mode === "login" ? "tab-button active" : "tab-button"} onClick={() => setMode("login")}>
              {t(locale, "Вход", "Login")}
            </button>
            <button type="button" className={mode === "register" ? "tab-button active" : "tab-button"} onClick={() => setMode("register")}>
              {t(locale, "Регистрация", "Register")}
            </button>
          </div>

          <label>
            <span>{t(locale, "Логин", "Username")}</span>
            <input value={username} onChange={(event) => setUsername(event.target.value)} />
          </label>

          <label>
            <span>{t(locale, "Пароль", "Password")}</span>
            <input type="password" value={password} onChange={(event) => setPassword(event.target.value)} />
          </label>

          {mode === "login" ? (
            <label className="checkbox-row">
              <input type="checkbox" checked={remember} onChange={(event) => setRemember(event.target.checked)} />
              <span>{t(locale, "Запомнить меня", "Remember me")}</span>
            </label>
          ) : null}

          <button type="submit" disabled={authLoading}>
            {authLoading
              ? t(locale, "Подождите...", "Please wait...")
              : mode === "login"
                ? t(locale, "Войти", "Sign in")
                : t(locale, "Создать аккаунт", "Create account")}
          </button>

          <p className="auth-note">
            {t(
              locale,
              "Первый зарегистрированный аккаунт автоматически становится владельцем и получает доступ к админке.",
              "The first registered account automatically becomes the owner and gets admin access.",
            )}
          </p>
        </form>
      </section>
    </div>
  );
}

export default function App() {
  const [locale, setLocale] = useState<Locale>("ru");
  const [toast, setToast] = useState<Toast>(null);
  const [session, setSession] = useState<SessionResponse | null>(null);
  const [authLoading, setAuthLoading] = useState(false);
  const [bootLoading, setBootLoading] = useState(true);
  const [domainsText, setDomainsText] = useState("example.com\nopenai.com");
  const [uploadFile, setUploadFile] = useState<File | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [job, setJob] = useState<JobStatusResponse | null>(null);
  const [activeJobId, setActiveJobId] = useState<string | null>(null);
  const [expandedDomain, setExpandedDomain] = useState<string | null>(null);
  const [resultQuery, setResultQuery] = useState("");
  const [resultStatus, setResultStatus] = useState("all");
  const [resultSort, setResultSort] = useState("risk");
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [historyDomain, setHistoryDomain] = useState("");
  const [historyDays, setHistoryDays] = useState("30");
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyStatusFilter, setHistoryStatusFilter] = useState("all");
  const [proxyUrl, setProxyUrl] = useState("");
  const [proxyFilter, setProxyFilter] = useState("");
  const [proxies, setProxies] = useState<ProxyEndpoint[]>([]);
  const [webhookUrl, setWebhookUrl] = useState("");
  const [webhookEvents, setWebhookEvents] = useState("job.completed,job.failed");
  const [webhooks, setWebhooks] = useState<WebhookSubscription[]>([]);
  const [watchDomain, setWatchDomain] = useState("");
  const [watchInterval, setWatchInterval] = useState("24");
  const [watchFilter, setWatchFilter] = useState("");
  const [watchlist, setWatchlist] = useState<WatchlistItem[]>([]);
  const [runtime, setRuntime] = useState<RuntimeSummary | null>(null);
  const [activeTab, setActiveTab] = useState<TabKey>("history");
  const [adminOverview, setAdminOverview] = useState<AdminOverview | null>(null);
  const [adminUsers, setAdminUsers] = useState<AdminUser[]>([]);
  const [providerSettings, setProviderSettings] = useState<Omit<ProviderSettings, "configured">>(emptyProviderSettings);
  const [providerConfigured, setProviderConfigured] = useState<Record<string, boolean>>({});
  const [providerSaving, setProviderSaving] = useState(false);

  useEffect(() => {
    void bootstrap();
  }, []);

  useEffect(() => {
    if (!session) return;
    setLocale(session.user.language);
    void loadWorkspace(session);
  }, [session]);

  useEffect(() => {
    if (!activeJobId || !session) return;

    let cancelled = false;
    let source: EventSource | null = null;
    let fallbackTimer = 0;

    const fallbackPoll = async () => {
      try {
        const status = await api.getStatus(activeJobId);
        if (cancelled) return;
        setJob(status);
        if (status.reports.length && !expandedDomain) setExpandedDomain(status.reports[0].domain);
        if (status.status === "completed") {
          setToast({ type: "success", text: t(locale, "Проверка завершена.", "Scan completed.") });
          void loadHistory(historyDomain, historyDays);
          return;
        }
        if (status.status === "failed") {
          setToast({ type: "error", text: status.last_error || t(locale, "Задача завершилась ошибкой.", "Job failed.") });
          return;
        }
        fallbackTimer = window.setTimeout(() => void fallbackPoll(), 2000);
      } catch (error) {
        if (!cancelled) {
          setToast({ type: "error", text: error instanceof Error ? error.message : "Failed to load job status." });
        }
      }
    };

    try {
      source = new EventSource(api.streamStatusUrl(activeJobId), { withCredentials: true });
      source.addEventListener("status", (event) => {
        const nextStatus = JSON.parse((event as MessageEvent).data) as JobStatusResponse;
        if (cancelled) return;
        setJob(nextStatus);
        if (nextStatus.reports.length && !expandedDomain) setExpandedDomain(nextStatus.reports[0].domain);
        if (nextStatus.status === "completed") {
          setToast({ type: "success", text: t(locale, "Проверка завершена.", "Scan completed.") });
          void loadHistory(historyDomain, historyDays);
          source?.close();
        }
        if (nextStatus.status === "failed") {
          setToast({ type: "error", text: nextStatus.last_error || t(locale, "Задача завершилась ошибкой.", "Job failed.") });
          source?.close();
        }
      });
      source.onerror = () => {
        source?.close();
        if (!cancelled) void fallbackPoll();
      };
    } catch {
      void fallbackPoll();
    }

    return () => {
      cancelled = true;
      if (fallbackTimer) window.clearTimeout(fallbackTimer);
      source?.close();
    };
  }, [activeJobId, session, expandedDomain, historyDomain, historyDays, locale]);

  async function bootstrap() {
    try {
      const current = await api.getMe();
      setSession(current);
      setLocale(current.user.language);
    } catch {
      setSession(null);
    } finally {
      setBootLoading(false);
    }
  }

  async function loadWorkspace(currentSession: SessionResponse) {
    await Promise.all([
      loadHistory(historyDomain, historyDays),
      loadProxies(),
      loadWebhooks(),
      loadWatchlist(),
      loadRuntime(),
      ...(currentSession.user.role === "owner" || currentSession.user.role === "admin"
        ? [loadAdminOverview(), loadAdminUsers(), loadProviderSettings()]
        : []),
    ]);
  }

  async function loadHistory(domain: string, days: string) {
    setHistoryLoading(true);
    try {
      setHistory(await api.getHistory(domain, Number(days)));
    } catch (error) {
      setToast({ type: "error", text: error instanceof Error ? error.message : "Failed to load history." });
    } finally {
      setHistoryLoading(false);
    }
  }

  async function loadProxies() {
    try {
      setProxies(await api.getProxies());
    } catch (error) {
      setToast({ type: "error", text: error instanceof Error ? error.message : "Failed to load proxies." });
    }
  }

  async function loadWebhooks() {
    try {
      setWebhooks(await api.getWebhooks());
    } catch (error) {
      setToast({ type: "error", text: error instanceof Error ? error.message : "Failed to load webhooks." });
    }
  }

  async function loadWatchlist() {
    try {
      setWatchlist(await api.getWatchlist());
    } catch (error) {
      setToast({ type: "error", text: error instanceof Error ? error.message : "Failed to load watchlist." });
    }
  }

  async function loadRuntime() {
    try {
      setRuntime(await api.getRuntimeSummary());
    } catch (error) {
      setToast({ type: "error", text: error instanceof Error ? error.message : "Failed to load runtime summary." });
    }
  }

  async function loadAdminOverview() {
    try {
      setAdminOverview(await api.getAdminOverview());
    } catch (error) {
      setToast({ type: "error", text: error instanceof Error ? error.message : "Failed to load admin overview." });
    }
  }

  async function loadAdminUsers() {
    try {
      setAdminUsers(await api.getAdminUsers());
    } catch (error) {
      setToast({ type: "error", text: error instanceof Error ? error.message : "Failed to load users." });
    }
  }

  async function loadProviderSettings() {
    try {
      const payload = await api.getProviderSettings();
      const { configured, ...values } = payload;
      setProviderSettings(values);
      setProviderConfigured(configured);
    } catch (error) {
      setToast({ type: "error", text: error instanceof Error ? error.message : "Failed to load provider settings." });
    }
  }

  async function handleLogin(username: string, password: string, remember: boolean) {
    setAuthLoading(true);
    try {
      setSession(await api.login(username, password, remember));
      setToast({ type: "success", text: t(locale, "Вход выполнен.", "Signed in.") });
    } catch (error) {
      setToast({ type: "error", text: error instanceof Error ? error.message : t(locale, "Ошибка входа.", "Login failed.") });
    } finally {
      setAuthLoading(false);
    }
  }

  async function handleRegister(username: string, password: string) {
    setAuthLoading(true);
    try {
      setSession(await api.register(username, password, locale));
      setToast({ type: "success", text: t(locale, "Аккаунт создан.", "Account created.") });
    } catch (error) {
      setToast({ type: "error", text: error instanceof Error ? error.message : t(locale, "Ошибка регистрации.", "Registration failed.") });
    } finally {
      setAuthLoading(false);
    }
  }

  async function handleLogout() {
    try {
      await api.logout();
    } finally {
      setSession(null);
      setJob(null);
      setActiveJobId(null);
      setHistory([]);
      setProxies([]);
      setWebhooks([]);
      setWatchlist([]);
      setRuntime(null);
      setAdminOverview(null);
      setAdminUsers([]);
      setProviderSettings(emptyProviderSettings);
      setProviderConfigured({});
    }
  }

  async function handleLanguageSwitch(nextLocale: Locale) {
    setLocale(nextLocale);
    if (!session) return;
    try {
      setSession(await api.updateProfile(nextLocale));
    } catch (error) {
      setToast({ type: "error", text: error instanceof Error ? error.message : "Failed to switch language." });
    }
  }

  async function handleSubmit(event: FormEvent) {
    event.preventDefault();
    setSubmitting(true);
    setToast(null);
    try {
      const created = uploadFile
        ? await api.createCheckFromFile(uploadFile)
        : await (async () => {
            const domains = parseDomains(domainsText);
            if (!domains.length) {
              throw new Error(t(locale, "Добавь хотя бы один домен.", "Add at least one domain."));
            }
            return api.createCheck(domains);
          })();
      setActiveJobId(created.job_id);
      setJob(null);
      setExpandedDomain(null);
      setToast({
        type: "success",
        text: t(locale, `Создана задача ${created.job_id} на ${created.total_domains} доменов.`, `Job ${created.job_id} created for ${created.total_domains} domains.`),
      });
      await loadHistory(historyDomain, historyDays);
      setActiveTab("history");
    } catch (error) {
      setToast({ type: "error", text: error instanceof Error ? error.message : t(locale, "Не удалось запустить проверку.", "Failed to start scan.") });
    } finally {
      setSubmitting(false);
    }
  }

  async function handleFileUpload(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) {
      setUploadFile(null);
      return;
    }
    setUploadFile(file);
    const content = await file.text();
    setDomainsText((current) => `${current.trim() ? `${current}\n` : ""}${content}`.trim());
  }

  async function handleProxySubmit(event: FormEvent) {
    event.preventDefault();
    try {
      if (!proxyUrl.trim()) {
        throw new Error(t(locale, "Введите proxy URL.", "Enter a proxy URL."));
      }
      await api.createProxy(proxyUrl.trim());
      setProxyUrl("");
      setToast({ type: "success", text: t(locale, "Прокси сохранён.", "Proxy saved.") });
      await loadProxies();
      await loadRuntime();
    } catch (error) {
      setToast({ type: "error", text: error instanceof Error ? error.message : t(locale, "Ошибка сохранения прокси.", "Failed to save proxy.") });
    }
  }

  async function toggleProxy(proxy: ProxyEndpoint) {
    try {
      await api.updateProxy(proxy.id, !proxy.is_active);
      await loadProxies();
      await loadRuntime();
    } catch (error) {
      setToast({ type: "error", text: error instanceof Error ? error.message : t(locale, "Ошибка обновления прокси.", "Failed to update proxy.") });
    }
  }

  async function removeProxy(proxyId: number) {
    try {
      await api.deleteProxy(proxyId);
      await loadProxies();
      await loadRuntime();
    } catch (error) {
      setToast({ type: "error", text: error instanceof Error ? error.message : t(locale, "Ошибка удаления прокси.", "Failed to delete proxy.") });
    }
  }

  async function handleWebhookSubmit(event: FormEvent) {
    event.preventDefault();
    try {
      const events = webhookEvents.split(",").map((item) => item.trim()).filter(Boolean);
      if (!webhookUrl.trim() || !events.length) {
        throw new Error(t(locale, "Заполни URL и события.", "Enter webhook URL and events."));
      }
      await api.createWebhook(webhookUrl.trim(), events);
      setWebhookUrl("");
      setToast({ type: "success", text: t(locale, "Webhook сохранён.", "Webhook saved.") });
      await loadWebhooks();
    } catch (error) {
      setToast({ type: "error", text: error instanceof Error ? error.message : t(locale, "Ошибка сохранения webhook.", "Failed to save webhook.") });
    }
  }

  async function removeWebhook(webhookId: number) {
    try {
      await api.deleteWebhook(webhookId);
      await loadWebhooks();
    } catch (error) {
      setToast({ type: "error", text: error instanceof Error ? error.message : t(locale, "Ошибка удаления webhook.", "Failed to delete webhook.") });
    }
  }

  async function testWebhookNow(webhookId: number) {
    try {
      await api.testWebhook(webhookId);
      setToast({ type: "success", text: t(locale, "Тестовый webhook отправлен.", "Test webhook sent.") });
    } catch (error) {
      setToast({ type: "error", text: error instanceof Error ? error.message : t(locale, "Ошибка тестового webhook.", "Failed to send test webhook.") });
    }
  }

  async function handleWatchSubmit(event: FormEvent) {
    event.preventDefault();
    try {
      if (!watchDomain.trim()) {
        throw new Error(t(locale, "Введите домен для watchlist.", "Enter a domain for the watchlist."));
      }
      await api.createWatchlist(watchDomain.trim(), Number(watchInterval));
      setWatchDomain("");
      setToast({ type: "success", text: t(locale, "Домен добавлен в watchlist.", "Watchlist item saved.") });
      await loadWatchlist();
      await loadRuntime();
    } catch (error) {
      setToast({ type: "error", text: error instanceof Error ? error.message : t(locale, "Ошибка сохранения watchlist.", "Failed to save watchlist item.") });
    }
  }

  async function toggleWatch(item: WatchlistItem) {
    try {
      await api.updateWatchlist(item.id, { is_active: !item.is_active });
      await loadWatchlist();
      await loadRuntime();
    } catch (error) {
      setToast({ type: "error", text: error instanceof Error ? error.message : t(locale, "Ошибка обновления watchlist.", "Failed to update watchlist item.") });
    }
  }

  async function runWatchNow(item: WatchlistItem) {
    try {
      const updated = await api.runWatchlistNow(item.id);
      if (updated.last_job_id) setActiveJobId(updated.last_job_id);
      await loadWatchlist();
    } catch (error) {
      setToast({ type: "error", text: error instanceof Error ? error.message : t(locale, "Ошибка запуска watchlist.", "Failed to run watchlist item.") });
    }
  }

  async function removeWatch(itemId: number) {
    try {
      await api.deleteWatchlist(itemId);
      await loadWatchlist();
      await loadRuntime();
    } catch (error) {
      setToast({ type: "error", text: error instanceof Error ? error.message : t(locale, "Ошибка удаления watchlist.", "Failed to delete watchlist item.") });
    }
  }

  async function saveProviderSettings(event: FormEvent) {
    event.preventDefault();
    setProviderSaving(true);
    try {
      const payload = await api.updateProviderSettings(providerSettings);
      const { configured, ...values } = payload;
      setProviderSettings(values);
      setProviderConfigured(configured);
      setToast({ type: "success", text: t(locale, "Настройки провайдеров сохранены.", "Provider settings saved.") });
      await loadRuntime();
    } catch (error) {
      setToast({ type: "error", text: error instanceof Error ? error.message : t(locale, "Ошибка сохранения настроек.", "Failed to save settings.") });
    } finally {
      setProviderSaving(false);
    }
  }

  async function updateUserStatus(userId: number, payload: Partial<Pick<AdminUser, "status" | "role">>) {
    try {
      await api.updateAdminUser(userId, payload);
      await loadAdminUsers();
    } catch (error) {
      setToast({ type: "error", text: error instanceof Error ? error.message : t(locale, "Ошибка обновления пользователя.", "Failed to update user.") });
    }
  }

  const reports = job?.reports ?? [];
  const filteredReports = useMemo(() => {
    const normalizedQuery = resultQuery.trim().toLowerCase();
    const base = reports.filter((report) => {
      if (resultStatus !== "all" && report.overall_status !== resultStatus) return false;
      if (normalizedQuery && !report.domain.toLowerCase().includes(normalizedQuery)) return false;
      return true;
    });
    const sorted = [...base];
    if (resultSort === "risk") {
      sorted.sort((left, right) => right.risk_score - left.risk_score || left.domain.localeCompare(right.domain));
    } else {
      sorted.sort((left, right) => Date.parse(right.checked_at) - Date.parse(left.checked_at));
    }
    return sorted;
  }, [reports, resultQuery, resultSort, resultStatus]);

  const filteredHistory = useMemo(
    () => history.filter((item) => historyStatusFilter === "all" || item.overall_status === historyStatusFilter),
    [history, historyStatusFilter],
  );
  const filteredProxies = useMemo(() => {
    const query = proxyFilter.trim().toLowerCase();
    return proxies.filter((item) => !query || item.display_url.toLowerCase().includes(query));
  }, [proxies, proxyFilter]);
  const filteredWatchlist = useMemo(() => {
    const query = watchFilter.trim().toLowerCase();
    return watchlist.filter((item) => !query || item.domain.toLowerCase().includes(query));
  }, [watchlist, watchFilter]);

  const currentAverageRisk = averageRisk(reports);
  const currentTopRisk = filteredReports[0]?.risk_score ?? reports[0]?.risk_score ?? 0;

  if (bootLoading) {
    return <div className="splash-screen">Loading...</div>;
  }

  if (!session) {
    return (
      <>
        {toast ? <div className={`toast floating ${toast.type}`}>{toast.text}</div> : null}
        <AuthScreen locale={locale} onLogin={handleLogin} onRegister={handleRegister} authLoading={authLoading} />
      </>
    );
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <div>
          <p className="eyebrow">{t(locale, "Изолированные аккаунты и глобальная админка", "Isolated users and global admin")}</p>
          <h1>Domain Blacklist Checker</h1>
        </div>
        <div className="topbar-actions">
          <div className="lang-switch">
            <button type="button" className={locale === "ru" ? "tab-button active" : "tab-button"} onClick={() => void handleLanguageSwitch("ru")}>
              RU
            </button>
            <button type="button" className={locale === "en" ? "tab-button active" : "tab-button"} onClick={() => void handleLanguageSwitch("en")}>
              EN
            </button>
          </div>
          <div className="user-chip">
            <strong>{session.user.username}</strong>
            <span>{session.user.role}</span>
          </div>
          <button type="button" className="ghost-button" onClick={() => void handleLogout()}>
            {t(locale, "Выйти", "Logout")}
          </button>
        </div>
      </header>

      {toast ? <div className={`toast ${toast.type}`}>{toast.text}</div> : null}
      {!session.has_feature_access ? (
        <div className="notice-block">
          <strong>{t(locale, "Доступ ограничен.", "Access is limited.")}</strong>
          <p>{session.user.status_message || t(locale, "Обратись к администратору.", "Contact an administrator.")}</p>
        </div>
      ) : null}

      <section className="hero dashboard-grid">
        <div className="results-top">
          <div className="card-head">
            <div>
              <h2>{t(locale, "Результаты текущей проверки", "Current scan results")}</h2>
              <p className="muted">{t(locale, "Сверху только краткая суть. Полные детали открываются отдельно.", "The top shows the short summary first. Full details open separately.")}</p>
            </div>
            <div className="hero-mini-stats">
              <div className="mini-stat">
                <span>{t(locale, "Средний риск", "Average risk")}</span>
                <strong>{currentAverageRisk}</strong>
              </div>
              <div className="mini-stat">
                <span>{t(locale, "Пиковый риск", "Top risk")}</span>
                <strong>{currentTopRisk}</strong>
              </div>
            </div>
          </div>

          <div className="filter-row">
            <label>
              <span>{t(locale, "Поиск по домену", "Search by domain")}</span>
              <input value={resultQuery} onChange={(event) => setResultQuery(event.target.value)} />
            </label>
            <label>
              <span>{t(locale, "Статус", "Status")}</span>
              <select value={resultStatus} onChange={(event) => setResultStatus(event.target.value)}>
                <option value="all">{t(locale, "Все", "All")}</option>
                <option value="listed">{t(locale, "В листинге", "Listed")}</option>
                <option value="warning">{t(locale, "Риск", "Warning")}</option>
                <option value="clean">{t(locale, "Чисто", "Clean")}</option>
              </select>
            </label>
            <label>
              <span>{t(locale, "Сортировка", "Sort")}</span>
              <select value={resultSort} onChange={(event) => setResultSort(event.target.value)}>
                <option value="risk">{t(locale, "По риску", "By risk")}</option>
                <option value="date">{t(locale, "По времени", "By time")}</option>
              </select>
            </label>
          </div>

          {!filteredReports.length ? <p className="empty-block">{t(locale, "Результатов пока нет. Запусти проверку справа.", "No results yet. Start a scan on the right.")}</p> : null}
          <div className="result-stack">
            {filteredReports.map((report) => {
              const expanded = expandedDomain === report.domain;
              const listedBlacklists = report.blacklists.filter((item) => item.listed);
              const virusTotal = findProvider(report, "VirusTotal");
              const phishTank = findProvider(report, "PhishTank");
              const abuseIpdb = findProvider(report, "AbuseIPDB");
              const urlhaus = findProvider(report, "URLhaus");
              const talos = findProvider(report, "Cisco Talos");
              return (
                <article key={report.domain} className="report-card compact-report">
                  <div className="report-card-head">
                    <div className="result-main">
                      <div className="domain-title-row">
                        <h3>{report.domain}</h3>
                        <StatusBadge status={report.overall_status} locale={locale} />
                      </div>
                      <p className="domain-summary-line">
                        {t(locale, "Проверено", "Checked")} {formatDate(locale, report.checked_at)} | DNSBL {listedBlacklists.length} | Safe Browsing {report.safe_browsing.status}
                      </p>
                      <div className="pill-row">
                        <span className="muted-chip">SPF {report.email_auth.spf}</span>
                        <span className="muted-chip">DKIM {report.email_auth.dkim}</span>
                        <span className="muted-chip">DMARC {report.email_auth.dmarc}</span>
                        <span className="muted-chip">VT {virusTotal?.status ?? "unknown"}</span>
                        <span className="muted-chip">PhishTank {phishTank?.status ?? "unknown"}</span>
                      </div>
                    </div>
                    <div className="result-side">
                      <div className={`risk-ring tone-${scoreTone(report.risk_score)}`}>
                        <strong>{report.risk_score}</strong>
                        <span>risk</span>
                      </div>
                      <button type="button" className="ghost-button" onClick={() => setExpandedDomain(expanded ? null : report.domain)}>
                        {expanded ? t(locale, "Скрыть", "Hide") : t(locale, "Подробнее", "Details")}
                      </button>
                    </div>
                  </div>

                  {expanded ? (
                    <div className="detail-grid">
                      <div className="detail-panel">
                        <h4>
                          {t(locale, "Провайдеры и источники", "Providers and sources")}
                          <Hint text={t(locale, "Если видишь unknown, значит ключ не настроен или источник не ответил.", "If you see unknown, the key is missing or the provider did not answer.")} />
                        </h4>
                        <div className="provider-grid">
                          <div className="provider-card"><span>Safe Browsing</span><strong>{report.safe_browsing.status}</strong><p>{report.safe_browsing.note ?? t(locale, "Совпадений нет.", "No matches found.")}</p></div>
                          <div className="provider-card"><span>VirusTotal</span><strong>{virusTotal?.status ?? "unknown"}</strong><p>{virusTotal?.note ?? t(locale, "Нет данных.", "No data.")}</p></div>
                          <div className="provider-card"><span>PhishTank</span><strong>{phishTank?.status ?? "unknown"}</strong><p>{phishTank?.note ?? t(locale, "Нет данных.", "No data.")}</p></div>
                          <div className="provider-card"><span>AbuseIPDB</span><strong>{abuseIpdb?.status ?? "unknown"}</strong><p>{abuseIpdb?.note ?? t(locale, "Нет данных.", "No data.")}</p></div>
                          <div className="provider-card"><span>URLhaus</span><strong>{urlhaus?.status ?? "unknown"}</strong><p>{urlhaus?.note ?? t(locale, "Нет данных.", "No data.")}</p></div>
                          <div className="provider-card"><span>Cisco Talos</span><strong>{talos?.status ?? "unknown"}</strong><p>{talos?.note ?? t(locale, "Нет данных.", "No data.")}</p></div>
                          <div className="provider-card"><span>Lumen</span><strong>{report.lumen.total_notices}</strong><p>{report.lumen.note ?? t(locale, "Уведомлений не найдено.", "No notices found.")}</p></div>
                        </div>
                        <div className="table-wrap">
                          <table>
                            <thead>
                              <tr>
                                <th>{t(locale, "Источник", "Source")}</th>
                                <th>{t(locale, "Категория", "Category")}</th>
                                <th>{t(locale, "Причина", "Reason")}</th>
                              </tr>
                            </thead>
                            <tbody>
                              {listedBlacklists.length ? listedBlacklists.map((item) => (
                                <tr key={`${report.domain}-${item.source}`}>
                                  <td>{item.source}</td>
                                  <td>{item.category ?? "dnsbl"}</td>
                                  <td>{item.reason ?? t(locale, "Срабатывание найдено.", "Match detected.")}</td>
                                </tr>
                              )) : (
                                <tr>
                                  <td colSpan={3}>{t(locale, "По DNSBL совпадений не найдено.", "No DNSBL matches found.")}</td>
                                </tr>
                              )}
                            </tbody>
                          </table>
                        </div>
                      </div>
                      <div className="detail-panel">
                        <h4>
                          {t(locale, "Расшифровка", "Explanation")}
                          <Hint text={t(locale, "Risk score собирается из DNSBL, Safe Browsing, reputation providers, Lumen и email auth. Чем выше число, тем выше риск.", "Risk score is built from DNSBL, Safe Browsing, reputation providers, Lumen, and email auth. The higher the number, the higher the risk.")} />
                        </h4>
                        <div className="key-value compact">
                          <div><span>Risk score <Hint text={t(locale, "Итоговая оценка риска от 0 до 100.", "Final risk score from 0 to 100.")} /></span><strong>{report.risk_score}</strong></div>
                          <div><span>Runtime <Hint text={t(locale, "Текущие лимиты очереди, прокси и watchlist.", "Current queue, proxy, and watchlist limits.")} /></span><strong>{runtime ? `${runtime.max_parallel_jobs} / ${runtime.watch_scheduler_poll_seconds}s` : "..."}</strong></div>
                          <div><span>Email auth</span><strong>{`SPF ${report.email_auth.spf}, DKIM ${report.email_auth.dkim}, DMARC ${report.email_auth.dmarc}`}</strong></div>
                        </div>
                        <h4>{t(locale, "Рекомендации", "Recommendations")}</h4>
                        <ul className="recommendation-list">
                          {report.recommendations.map((item) => <li key={`${report.domain}-${item}`}>{item}</li>)}
                        </ul>
                      </div>
                    </div>
                  ) : null}
                </article>
              );
            })}
          </div>
        </div>
        <div className="stack">
          <div className="card">
            <div className="card-head">
              <div>
                <h2>{t(locale, "Новая проверка", "New scan")}</h2>
                <p className="muted">{t(locale, "Можно вставить домены вручную или загрузить список. Результаты появятся сразу сверху слева.", "Paste domains manually or upload a list. Results will appear immediately at the top-left.")}</p>
              </div>
            </div>
            <form className="form" onSubmit={(event) => void handleSubmit(event)}>
              <label>
                <span>{t(locale, "Домены", "Domains")}</span>
                <textarea className="domain-textarea" value={domainsText} onChange={(event) => setDomainsText(event.target.value)} placeholder={"example.com\nexample.org\nsubdomain.example.net"} />
              </label>
              <label className="file-field">
                <span>{t(locale, "Файл со списком", "Upload list")}</span>
                <input type="file" accept=".txt,.csv" onChange={handleFileUpload} />
              </label>
              <button type="submit" disabled={submitting || !session.has_feature_access}>
                {submitting ? t(locale, "Запуск...", "Starting...") : t(locale, "Запустить проверку", "Run scan")}
              </button>
            </form>
            <div className="progress-wrap">
              <div className="progress-head">
                <strong>{t(locale, "Прогресс", "Progress")} <Hint text={t(locale, "Показывает, сколько доменов уже обработано в текущем job.", "Shows how many domains are already processed in the current job.")} /></strong>
                <span className="muted">{job ? `${job.progress}%` : t(locale, "Ожидание", "Idle")}</span>
              </div>
              <div className="progress-bar"><div className="progress-fill" style={{ width: `${job?.progress ?? 0}%` }} /></div>
              <p className="muted progress-note">Job ID: <span className="mono">{activeJobId ?? t(locale, "не запущено", "not started")}</span></p>
            </div>
          </div>

          <div className="card">
            <h2>{t(locale, "Быстрая сводка", "Quick summary")}</h2>
            <div className="summary-grid">
              <div className="snapshot-box"><span>{t(locale, "В листинге", "Listed")}</span><strong>{metricValue(reports, "listed")}</strong></div>
              <div className="snapshot-box"><span>{t(locale, "Риск", "Warning")}</span><strong>{metricValue(reports, "warning")}</strong></div>
              <div className="snapshot-box"><span>{t(locale, "Чисто", "Clean")}</span><strong>{metricValue(reports, "clean")}</strong></div>
              <div className="snapshot-box"><span>{t(locale, "Последнее обновление", "Last update")}</span><strong>{formatDate(locale, job?.finished_at ?? job?.started_at ?? null)}</strong></div>
            </div>
          </div>

          <div className="card">
            <h2>Runtime <Hint text={t(locale, "Текущие лимиты очереди, работа прокси, частота watchlist и глобальные провайдеры.", "Current queue limits, proxy behavior, watchlist frequency, and global providers.")} /></h2>
            <div className="key-value compact">
              <div><span>{t(locale, "HTTP стратегия", "HTTP strategy")}</span><strong>{runtime ? `${runtime.proxy_attempts_per_request} / ${providerStateLabel(locale, runtime.direct_http_fallback)}` : "..."}</strong></div>
              <div><span>{t(locale, "Очередь", "Queue")}</span><strong>{runtime ? `${runtime.max_parallel_jobs} | ${runtime.check_rate_limit_per_minute}/min` : "..."}</strong></div>
              <div><span>Watchlist</span><strong>{runtime ? `${runtime.active_watchlist} | ${runtime.watch_scheduler_poll_seconds}s` : "..."}</strong></div>
              <div><span>{t(locale, "Провайдеры", "Providers")}</span><strong>{runtime ? Object.entries(runtime.configured_providers).filter(([, enabled]) => enabled).map(([key]) => key).join(", ") || t(locale, "ключи не настроены", "no keys configured") : "..."}</strong></div>
            </div>
          </div>

          <div className="card">
            <h2>{t(locale, "Экспорт", "Exports")}</h2>
            <div className="actions">
              <a className={`button-link ${!activeJobId ? "disabled-link" : ""}`} href={activeJobId ? api.reportUrl(activeJobId, "json") : "#"}>JSON</a>
              <a className={`button-link ghost-link ${!activeJobId ? "disabled-link" : ""}`} href={activeJobId ? api.reportUrl(activeJobId, "csv") : "#"}>CSV</a>
              <a className={`button-link ghost-link ${!activeJobId ? "disabled-link" : ""}`} href={activeJobId ? api.reportUrl(activeJobId, "pdf") : "#"}>PDF</a>
            </div>
          </div>
        </div>
      </section>

      <section className="card nav-card">
        <div className="tabs">
          <button type="button" className={activeTab === "history" ? "tab-button active" : "tab-button"} onClick={() => setActiveTab("history")}>{t(locale, "История", "History")}</button>
          <button type="button" className={activeTab === "watchlist" ? "tab-button active" : "tab-button"} onClick={() => setActiveTab("watchlist")}>Watchlist</button>
          <button type="button" className={activeTab === "proxies" ? "tab-button active" : "tab-button"} onClick={() => setActiveTab("proxies")}>Proxies</button>
          <button type="button" className={activeTab === "webhooks" ? "tab-button active" : "tab-button"} onClick={() => setActiveTab("webhooks")}>Webhooks</button>
          {session.user.role === "owner" || session.user.role === "admin" ? <button type="button" className={activeTab === "admin" ? "tab-button active" : "tab-button"} onClick={() => setActiveTab("admin")}>{t(locale, "Админка", "Admin")}</button> : null}
        </div>

        {activeTab === "history" ? (
          <div className="tab-panel">
            <div className="card-head">
              <div>
                <h2>{t(locale, "Личная история проверок", "Personal check history")}</h2>
                <p className="muted">{t(locale, "Здесь только твои чеки. Чужие задачи и история не видны.", "Only your own jobs are shown here. Other users remain hidden.")}</p>
              </div>
            </div>
            <form className="filter-row" onSubmit={(event) => { event.preventDefault(); void loadHistory(historyDomain, historyDays); }}>
              <label><span>{t(locale, "Домен", "Domain")}</span><input value={historyDomain} onChange={(event) => setHistoryDomain(event.target.value)} /></label>
              <label><span>{t(locale, "Период", "Period")}</span><select value={historyDays} onChange={(event) => setHistoryDays(event.target.value)}><option value="7">{t(locale, "7 дней", "7 days")}</option><option value="30">{t(locale, "30 дней", "30 days")}</option><option value="90">{t(locale, "90 дней", "90 days")}</option></select></label>
              <label><span>{t(locale, "Статус", "Status")}</span><select value={historyStatusFilter} onChange={(event) => setHistoryStatusFilter(event.target.value)}><option value="all">{t(locale, "Все", "All")}</option><option value="listed">{t(locale, "В листинге", "Listed")}</option><option value="warning">{t(locale, "Риск", "Warning")}</option><option value="clean">{t(locale, "Чисто", "Clean")}</option></select></label>
              <button type="submit">{historyLoading ? t(locale, "Загрузка...", "Loading...") : t(locale, "Обновить", "Refresh")}</button>
            </form>
            <div className="history-list">
              {filteredHistory.map((item) => (
                <article key={`${item.job_id}-${item.domain}-${item.checked_at}`} className="history-row">
                  <div><strong>{item.domain}</strong><p>{formatDate(locale, item.checked_at)} | job {item.job_id}</p></div>
                  <div className="history-metrics"><StatusBadge status={item.overall_status} locale={locale} /><strong>{item.risk_score}</strong></div>
                </article>
              ))}
              {!filteredHistory.length ? <p className="empty-block">{t(locale, "История пока пуста.", "History is empty so far.")}</p> : null}
            </div>
          </div>
        ) : null}

        {activeTab === "watchlist" ? (
          <div className="tab-panel">
            <div className="card-head"><div><h2>Watchlist <Hint text={t(locale, "Автоматические периодические проверки только для твоего аккаунта.", "Automatic periodic checks for your account only.")} /></h2></div></div>
            <form className="filter-row" onSubmit={(event) => void handleWatchSubmit(event)}>
              <label><span>{t(locale, "Домен", "Domain")}</span><input value={watchDomain} onChange={(event) => setWatchDomain(event.target.value)} /></label>
              <label><span>{t(locale, "Интервал", "Interval")}</span><select value={watchInterval} onChange={(event) => setWatchInterval(event.target.value)}><option value="6">6h</option><option value="12">12h</option><option value="24">24h</option><option value="48">48h</option><option value="72">72h</option></select></label>
              <label><span>{t(locale, "Фильтр", "Filter")}</span><input value={watchFilter} onChange={(event) => setWatchFilter(event.target.value)} /></label>
              <button type="submit">{t(locale, "Добавить", "Add")}</button>
            </form>
            <div className="proxy-list">
              {filteredWatchlist.map((item) => (
                <article key={item.id} className="proxy-row">
                  <div><strong>{item.domain}</strong><p>{t(locale, "Каждые", "Every")} {item.interval_hours}h | {item.is_active ? t(locale, "активен", "active") : t(locale, "пауза", "paused")}</p><p>{t(locale, "Следующая проверка", "Next check")} {formatDate(locale, item.next_check_at)}</p></div>
                  <div className="actions"><button type="button" onClick={() => void runWatchNow(item)}>{t(locale, "Запустить", "Run now")}</button><button type="button" onClick={() => void toggleWatch(item)}>{item.is_active ? t(locale, "Пауза", "Pause") : t(locale, "Продолжить", "Resume")}</button><button type="button" className="ghost-button" onClick={() => void removeWatch(item.id)}>{t(locale, "Удалить", "Delete")}</button></div>
                </article>
              ))}
              {!filteredWatchlist.length ? <p className="empty-block">{t(locale, "Watchlist пуст.", "Watchlist is empty.")}</p> : null}
            </div>
          </div>
        ) : null}

        {activeTab === "proxies" ? (
          <div className="tab-panel">
            <div className="card-head"><div><h2>Proxies <Hint text={t(locale, "Эти прокси используются только твоими HTTP-провайдерами. DNSBL по DNS через них не идёт.", "These proxies are only used by your HTTP-based providers. DNSBL DNS lookups do not use them.")} /></h2></div></div>
            <form className="filter-row" onSubmit={(event) => void handleProxySubmit(event)}>
              <label><span>Proxy URL</span><input value={proxyUrl} onChange={(event) => setProxyUrl(event.target.value)} placeholder="socks5://login:password@127.0.0.1:1080" /></label>
              <label><span>{t(locale, "Фильтр", "Filter")}</span><input value={proxyFilter} onChange={(event) => setProxyFilter(event.target.value)} /></label>
              <button type="submit">{t(locale, "Сохранить", "Save")}</button>
            </form>
            <div className="proxy-list">
              {filteredProxies.map((proxy) => (
                <article key={proxy.id} className="proxy-row">
                  <div><strong>{proxy.display_url}</strong><p>ok {proxy.success_count} | fail {proxy.fail_count} | {proxy.is_active ? t(locale, "активен", "active") : t(locale, "выключен", "disabled")}</p>{proxy.last_used_at ? <p>{t(locale, "Последнее использование", "Last used")} {formatDate(locale, proxy.last_used_at)}</p> : null}{proxy.last_error ? <p className="error-text">{proxy.last_error}</p> : null}</div>
                  <div className="actions"><button type="button" onClick={() => void toggleProxy(proxy)}>{proxy.is_active ? t(locale, "Выключить", "Disable") : t(locale, "Включить", "Enable")}</button><button type="button" className="ghost-button" onClick={() => void removeProxy(proxy.id)}>{t(locale, "Удалить", "Delete")}</button></div>
                </article>
              ))}
              {!filteredProxies.length ? <p className="empty-block">{t(locale, "Прокси пока не добавлены.", "No proxies configured yet.")}</p> : null}
            </div>
          </div>
        ) : null}

        {activeTab === "webhooks" ? (
          <div className="tab-panel">
            <div className="card-head"><div><h2>Webhooks</h2><p className="muted">{t(locale, "Webhook-и тоже отдельные по пользователю.", "Webhooks are isolated per user as well.")}</p></div></div>
            <form className="filter-row" onSubmit={(event) => void handleWebhookSubmit(event)}>
              <label><span>URL</span><input value={webhookUrl} onChange={(event) => setWebhookUrl(event.target.value)} placeholder="https://example.com/webhooks/domain-checker" /></label>
              <label><span>{t(locale, "События", "Events")}</span><input value={webhookEvents} onChange={(event) => setWebhookEvents(event.target.value)} /></label>
              <button type="submit">{t(locale, "Добавить", "Add")}</button>
            </form>
            <div className="proxy-list">
              {webhooks.map((hook) => (
                <article key={hook.id} className="proxy-row">
                  <div><strong>{hook.url}</strong><p>{hook.events.join(", ")}</p><p>{formatDate(locale, hook.created_at)}</p></div>
                  <div className="actions"><button type="button" onClick={() => void testWebhookNow(hook.id)}>{t(locale, "Тест", "Test")}</button><button type="button" className="ghost-button" onClick={() => void removeWebhook(hook.id)}>{t(locale, "Удалить", "Delete")}</button></div>
                </article>
              ))}
              {!webhooks.length ? <p className="empty-block">{t(locale, "Webhook-ов пока нет.", "No webhooks configured yet.")}</p> : null}
            </div>
          </div>
        ) : null}

        {activeTab === "admin" && (session.user.role === "owner" || session.user.role === "admin") ? (
          <div className="tab-panel admin-grid">
            <div className="card inset-card">
              <h2>{t(locale, "Обзор системы", "System overview")}</h2>
              <div className="summary-grid">
                <div className="snapshot-box"><span>{t(locale, "Пользователи", "Users")}</span><strong>{adminOverview?.total_users ?? 0}</strong></div>
                <div className="snapshot-box"><span>{t(locale, "Активные", "Active")}</span><strong>{adminOverview?.active_users ?? 0}</strong></div>
                <div className="snapshot-box"><span>{t(locale, "Всего jobs", "Total jobs")}</span><strong>{adminOverview?.total_jobs ?? 0}</strong></div>
                <div className="snapshot-box"><span>{t(locale, "Всего proxy/watch", "Total proxy/watch")}</span><strong>{(adminOverview?.total_proxies ?? 0) + (adminOverview?.total_watchlist ?? 0)}</strong></div>
              </div>
            </div>
            <div className="card inset-card">
              <div className="card-head"><div><h2>{t(locale, "Глобальные API и интеграции", "Global APIs and integrations")}</h2><p className="muted">{t(locale, "Эти ключи и URL работают для всех зарегистрированных пользователей сразу.", "These keys and endpoints apply to all registered users immediately.")}</p></div></div>
              <form className="form provider-form" onSubmit={(event) => void saveProviderSettings(event)}>
                <label><span>Google Safe Browsing API key</span><input value={providerSettings.google_safe_browsing_api_key ?? ""} onChange={(event) => setProviderSettings((current) => ({ ...current, google_safe_browsing_api_key: event.target.value }))} /></label>
                <label><span>Lumen Search URL</span><input value={providerSettings.lumen_search_url ?? ""} onChange={(event) => setProviderSettings((current) => ({ ...current, lumen_search_url: event.target.value }))} /></label>
                <label><span>VirusTotal API key</span><input value={providerSettings.virustotal_api_key ?? ""} onChange={(event) => setProviderSettings((current) => ({ ...current, virustotal_api_key: event.target.value }))} /></label>
                <label><span>PhishTank app key</span><input value={providerSettings.phishtank_app_key ?? ""} onChange={(event) => setProviderSettings((current) => ({ ...current, phishtank_app_key: event.target.value }))} /></label>
                <label><span>PhishTank user agent</span><input value={providerSettings.phishtank_user_agent ?? ""} onChange={(event) => setProviderSettings((current) => ({ ...current, phishtank_user_agent: event.target.value }))} /></label>
                <label><span>AbuseIPDB API key</span><input value={providerSettings.abuseipdb_api_key ?? ""} onChange={(event) => setProviderSettings((current) => ({ ...current, abuseipdb_api_key: event.target.value }))} /></label>
                <label><span>URLhaus API URL</span><input value={providerSettings.urlhaus_api_url ?? ""} onChange={(event) => setProviderSettings((current) => ({ ...current, urlhaus_api_url: event.target.value }))} /></label>
                <label><span>URLhaus Auth-Key</span><input value={providerSettings.urlhaus_auth_key ?? ""} onChange={(event) => setProviderSettings((current) => ({ ...current, urlhaus_auth_key: event.target.value }))} /></label>
                <label><span>Cisco Talos API URL</span><input value={providerSettings.talos_api_url ?? ""} onChange={(event) => setProviderSettings((current) => ({ ...current, talos_api_url: event.target.value }))} /></label>
                <label><span>Webhook signing secret</span><input value={providerSettings.webhook_signing_secret ?? ""} onChange={(event) => setProviderSettings((current) => ({ ...current, webhook_signing_secret: event.target.value }))} /></label>
                <button type="submit" disabled={providerSaving}>{providerSaving ? t(locale, "Сохранение...", "Saving...") : t(locale, "Сохранить настройки", "Save settings")}</button>
              </form>
              <div className="pill-row">{Object.entries(providerConfigured).map(([key, enabled]) => <span key={key} className={`muted-chip ${enabled ? "chip-enabled" : ""}`}>{key}: {enabled ? t(locale, "готово", "ready") : t(locale, "нет", "off")}</span>)}</div>
            </div>
            <div className="card inset-card admin-users-card">
              <div className="card-head"><div><h2>{t(locale, "Пользователи", "Users")}</h2><p className="muted">{t(locale, "Можно менять роли и статусы. Данные пользователей остаются разделёнными.", "You can change roles and statuses. User data remains isolated.")}</p></div></div>
              <div className="table-wrap">
                <table>
                  <thead><tr><th>{t(locale, "Логин", "Username")}</th><th>{t(locale, "Роль", "Role")}</th><th>{t(locale, "Статус", "Status")}</th><th>{t(locale, "Ресурсы", "Resources")}</th><th>{t(locale, "Действия", "Actions")}</th></tr></thead>
                  <tbody>
                    {adminUsers.map((user) => (
                      <tr key={user.id}>
                        <td><strong>{user.username}</strong><div className="table-subtext">{formatDate(locale, user.created_at)}</div></td>
                        <td>{user.role}</td>
                        <td>{user.status}</td>
                        <td>{`${user.job_count} jobs | ${user.proxy_count} proxy | ${user.watch_count} watch`}</td>
                        <td><div className="actions">{user.role === "user" ? <button type="button" onClick={() => void updateUserStatus(user.id, { role: "admin" })}>{t(locale, "Сделать admin", "Make admin")}</button> : null}{user.status !== "blocked" ? <button type="button" className="ghost-button" onClick={() => void updateUserStatus(user.id, { status: "blocked" })}>{t(locale, "Заблокировать", "Block")}</button> : <button type="button" onClick={() => void updateUserStatus(user.id, { status: "approved" })}>{t(locale, "Разблокировать", "Unblock")}</button>}</div></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        ) : null}
      </section>
    </div>
  );
}
