import { ChangeEvent, FormEvent, type CSSProperties, useEffect, useMemo, useState } from "react";

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
type TabKey = "guide" | "history" | "watchlist" | "proxies" | "webhooks" | "admin";

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

function riskRingColor(score: number) {
  if (score >= 60) return "#b23b2a";
  if (score > 0) return "#b77a1c";
  return "#1f7a46";
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

function LabelWithHint({ label, hint }: { label: string; hint?: string }) {
  return (
    <span className="label-with-hint">
      {label}
      {hint ? <Hint text={hint} /> : null}
    </span>
  );
}

function InfoPill({ label, value, hint }: { label: string; value: string; hint: string }) {
  return (
    <span className="muted-chip pill-with-hint">
      <LabelWithHint label={`${label} ${value}`} hint={hint} />
    </span>
  );
}

function downloadText(filename: string, content: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

function buildHistoryCsv(history: HistoryItem[]) {
  const rows = [
    ["domain", "job_id", "status", "risk_score", "checked_at"],
    ...history.map((item) => [item.domain, item.job_id, item.overall_status, String(item.risk_score), item.checked_at]),
  ];
  return rows.map((row) => row.map((cell) => `"${cell.replaceAll('"', '""')}"`).join(",")).join("\n");
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
  onLocaleChange,
  authLoading,
}: {
  locale: Locale;
  onLogin: (username: string, password: string, remember: boolean) => Promise<void>;
  onRegister: (username: string, password: string) => Promise<void>;
  onLocaleChange: (locale: Locale) => void;
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
      <section className="auth-card">
        <div className="auth-copy">
          <div className="lang-switch auth-lang-switch">
            <button type="button" className={locale === "ru" ? "tab-button active" : "tab-button"} onClick={() => onLocaleChange("ru")}>
              RU
            </button>
            <button type="button" className={locale === "en" ? "tab-button active" : "tab-button"} onClick={() => onLocaleChange("en")}>
              EN
            </button>
          </div>
          <h1>Domain Blacklist Checker</h1>
          <p className="subtitle">
            {t(
              locale,
              "Войдите в аккаунт или отправьте заявку на регистрацию.",
              "Sign in to your account or submit a registration request.",
            )}
          </p>
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
  const [expandedDomains, setExpandedDomains] = useState<string[]>([]);
  const [resultQuery, setResultQuery] = useState("");
  const [resultStatus, setResultStatus] = useState("all");
  const [resultSort, setResultSort] = useState("risk");
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [historyDomain, setHistoryDomain] = useState("");
  const [historyDays, setHistoryDays] = useState("30");
  const [historyLimit, setHistoryLimit] = useState("50");
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
  const [adminUserSaving, setAdminUserSaving] = useState(false);
  const [adminUserFilter, setAdminUserFilter] = useState("");
  const [passwordSaving, setPasswordSaving] = useState(false);
  const [adminPasswordSaving, setAdminPasswordSaving] = useState(false);
  const [adminUserForm, setAdminUserForm] = useState({
    username: "",
    password: "",
    role: "user",
    status: "approved",
    language: "ru" as Locale,
    max_domains: "",
  });
  const [passwordForm, setPasswordForm] = useState({
    current_password: "",
    new_password: "",
  });
  const [adminPasswordForm, setAdminPasswordForm] = useState({
    user_id: "",
    password: "",
  });

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
        if (status.status === "completed") {
          setToast({ type: "success", text: t(locale, "Проверка завершена.", "Scan completed.") });
          void loadHistory("", historyDays);
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
        if (nextStatus.status === "completed") {
          setToast({ type: "success", text: t(locale, "Проверка завершена.", "Scan completed.") });
          void loadHistory("", historyDays);
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
  }, [activeJobId, session, historyDays, locale]);

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
      ...(currentSession.has_feature_access
        ? [loadHistory("", historyDays), loadProxies(), loadWebhooks(), loadWatchlist(), loadRuntime()]
        : []),
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
    } catch (error) {
      setToast({ type: "error", text: error instanceof Error ? error.message : t(locale, "Ошибка выхода.", "Logout failed.") });
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
      setExpandedDomains([]);
      setToast({
        type: "success",
        text: t(locale, `Создана задача ${created.job_id} на ${created.total_domains} доменов.`, `Job ${created.job_id} created for ${created.total_domains} domains.`),
      });
      await loadHistory("", historyDays);
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

  async function handleAdminUserCreate(event: FormEvent) {
    event.preventDefault();
    setAdminUserSaving(true);
    try {
      await api.createAdminUser({
        username: adminUserForm.username,
        password: adminUserForm.password,
        role: adminUserForm.role,
        status: adminUserForm.status,
        language: adminUserForm.language,
        max_domains: adminUserForm.max_domains ? Number(adminUserForm.max_domains) : null,
        status_message: adminUserForm.status === "pending" ? t(locale, "Ожидает подтверждения администратора.", "Pending administrator approval.") : null,
      });
      setAdminUserForm({
        username: "",
        password: "",
        role: "user",
        status: "approved",
        language: locale,
        max_domains: "",
      });
      setToast({ type: "success", text: t(locale, "Пользователь создан.", "User created.") });
      await Promise.all([loadAdminUsers(), loadAdminOverview()]);
    } catch (error) {
      setToast({ type: "error", text: error instanceof Error ? error.message : t(locale, "Не удалось создать пользователя.", "Failed to create user.") });
    } finally {
      setAdminUserSaving(false);
    }
  }

  async function handlePasswordChange(event: FormEvent) {
    event.preventDefault();
    setPasswordSaving(true);
    try {
      const nextSession = await api.changePassword(passwordForm.current_password, passwordForm.new_password);
      setSession(nextSession);
      setPasswordForm({ current_password: "", new_password: "" });
      setToast({ type: "success", text: t(locale, "Пароль обновлён.", "Password updated.") });
    } catch (error) {
      setToast({ type: "error", text: error instanceof Error ? error.message : t(locale, "Не удалось обновить пароль.", "Failed to update password.") });
    } finally {
      setPasswordSaving(false);
    }
  }

  async function handleAdminPasswordReset(event: FormEvent) {
    event.preventDefault();
    if (!adminPasswordForm.user_id) {
      setToast({ type: "error", text: t(locale, "Выбери пользователя.", "Select a user.") });
      return;
    }
    setAdminPasswordSaving(true);
    try {
      await api.updateAdminUserPassword(Number(adminPasswordForm.user_id), adminPasswordForm.password);
      setAdminPasswordForm({ user_id: "", password: "" });
      setToast({ type: "success", text: t(locale, "Пароль пользователя обновлён.", "User password updated.") });
    } catch (error) {
      setToast({ type: "error", text: error instanceof Error ? error.message : t(locale, "Не удалось обновить пароль пользователя.", "Failed to update user password.") });
    } finally {
      setAdminPasswordSaving(false);
    }
  }

  async function updateUserStatus(
    userId: number,
    payload: Partial<Pick<AdminUser, "status" | "role" | "language" | "max_domains" | "status_message">>,
  ) {
    try {
      await api.updateAdminUser(userId, payload);
      await Promise.all([loadAdminUsers(), loadAdminOverview()]);
    } catch (error) {
      setToast({ type: "error", text: error instanceof Error ? error.message : t(locale, "Ошибка обновления пользователя.", "Failed to update user.") });
    }
  }

  function toggleExpandedDomain(domain: string) {
    setExpandedDomains((current) =>
      current.includes(domain) ? current.filter((item) => item !== domain) : [...current, domain],
    );
  }

  async function openHistoryDetails(item: HistoryItem) {
    try {
      const status = await api.getStatus(item.job_id);
      setJob(status);
      setActiveJobId(item.job_id);
      setExpandedDomains([item.domain]);
      window.scrollTo({ top: 0, behavior: "smooth" });
    } catch (error) {
      setToast({ type: "error", text: error instanceof Error ? error.message : t(locale, "Не удалось открыть детали истории.", "Failed to open history details.") });
    }
  }

  async function removeHistoryItem(itemId: number) {
    try {
      await api.deleteHistory(itemId);
      await loadHistory("", historyDays);
      setToast({ type: "success", text: t(locale, "Запись истории удалена.", "History item deleted.") });
    } catch (error) {
      setToast({ type: "error", text: error instanceof Error ? error.message : t(locale, "Не удалось удалить запись истории.", "Failed to delete history item.") });
    }
  }

  function exportHistoryJson(items: HistoryItem[]) {
    downloadText(
      "history-export.json",
      JSON.stringify(items, null, 2),
      "application/json;charset=utf-8",
    );
  }

  function exportHistoryCsv(items: HistoryItem[]) {
    downloadText("history-export.csv", buildHistoryCsv(items), "text/csv;charset=utf-8");
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

  const filteredHistory = useMemo(() => {
    const query = historyDomain.trim().toLowerCase();
    const filtered = history.filter((item) => {
      if (historyStatusFilter !== "all" && item.overall_status !== historyStatusFilter) return false;
      if (query && !item.domain.toLowerCase().includes(query)) return false;
      return true;
    });
    const limit = Math.max(Number(historyLimit) || filtered.length, 1);
    return filtered.slice(0, limit);
  }, [history, historyStatusFilter, historyDomain, historyLimit]);
  const filteredProxies = useMemo(() => {
    const query = proxyFilter.trim().toLowerCase();
    return proxies.filter((item) => !query || item.display_url.toLowerCase().includes(query));
  }, [proxies, proxyFilter]);
  const filteredWatchlist = useMemo(() => {
    const query = watchFilter.trim().toLowerCase();
    return watchlist.filter((item) => !query || item.domain.toLowerCase().includes(query));
  }, [watchlist, watchFilter]);
  const filteredAdminUsers = useMemo(() => {
    const query = adminUserFilter.trim().toLowerCase();
    return adminUsers.filter((item) => !query || item.username.toLowerCase().includes(query));
  }, [adminUsers, adminUserFilter]);

  const currentAverageRisk = averageRisk(reports);
  const currentTopRisk = filteredReports[0]?.risk_score ?? reports[0]?.risk_score ?? 0;
  const exportJobId = job?.job_id ?? activeJobId ?? history[0]?.job_id ?? null;

  if (bootLoading) {
    return <div className="splash-screen">Loading...</div>;
  }

  if (!session) {
    return (
      <>
        {toast ? <div className={`toast floating ${toast.type}`}>{toast.text}</div> : null}
        <AuthScreen locale={locale} onLogin={handleLogin} onRegister={handleRegister} onLocaleChange={setLocale} authLoading={authLoading} />
      </>
    );
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <div>
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

      {!session.has_feature_access ? null : (
      <>

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
              const expanded = expandedDomains.includes(report.domain);
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
                        <InfoPill label="SPF" value={report.email_auth.spf} hint={t(locale, "Показывает, найден ли SPF-запись домена для почтовой аутентификации.", "Shows whether an SPF record was found for email authentication.")} />
                        <InfoPill label="DKIM" value={report.email_auth.dkim} hint={t(locale, "Показывает, найден ли DKIM у стандартных селекторов домена.", "Shows whether DKIM was found on common selectors for the domain.")} />
                        <InfoPill label="DMARC" value={report.email_auth.dmarc} hint={t(locale, "Показывает, есть ли DMARC-политика для домена.", "Shows whether the domain has a DMARC policy.")} />
                        <InfoPill label="VT" value={virusTotal?.status ?? "unknown"} hint={t(locale, "Сводка репутации домена по данным VirusTotal.", "Domain reputation summary from VirusTotal.")} />
                        <InfoPill label="PhishTank" value={phishTank?.status ?? "unknown"} hint={t(locale, "Проверка домена на фишинговые совпадения через PhishTank.", "Checks the domain for phishing matches through PhishTank.")} />
                      </div>
                    </div>
                    <div className="result-side">
                      <div
                        className={`risk-ring tone-${scoreTone(report.risk_score)}`}
                        style={
                          {
                            "--risk-percent": `${report.risk_score}%`,
                            "--risk-color": riskRingColor(report.risk_score),
                          } as CSSProperties
                        }
                      >
                        <strong>{report.risk_score}</strong>
                        <span>risk</span>
                      </div>
                      <button type="button" className="ghost-button" onClick={() => toggleExpandedDomain(report.domain)}>
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
                          <div className="provider-card"><LabelWithHint label="Safe Browsing" hint={t(locale, "Google-проверка домена на malware, phishing и unwanted software.", "Google domain check for malware, phishing, and unwanted software.")} /><strong>{report.safe_browsing.status}</strong><p>{report.safe_browsing.note ?? t(locale, "Совпадений нет.", "No matches found.")}</p></div>
                          <div className="provider-card"><LabelWithHint label="VirusTotal" hint={t(locale, "Репутация домена по агрегированным антивирусным и reputation-источникам.", "Domain reputation from aggregated antivirus and reputation sources.")} /><strong>{virusTotal?.status ?? "unknown"}</strong><p>{virusTotal?.note ?? t(locale, "Нет данных.", "No data.")}</p></div>
                          <div className="provider-card"><LabelWithHint label="PhishTank" hint={t(locale, "Проверка на известные фишинговые совпадения.", "Checks for known phishing matches.")} /><strong>{phishTank?.status ?? "unknown"}</strong><p>{phishTank?.note ?? t(locale, "Нет данных.", "No data.")}</p></div>
                          <div className="provider-card"><LabelWithHint label="AbuseIPDB" hint={t(locale, "Оценка злоупотреблений по IP-адресу домена.", "Abuse reputation estimate for the domain IP address.")} /><strong>{abuseIpdb?.status ?? "unknown"}</strong><p>{abuseIpdb?.note ?? t(locale, "Нет данных.", "No data.")}</p></div>
                          <div className="provider-card"><LabelWithHint label="URLhaus" hint={t(locale, "Проверка домена на вредоносные URL и malware-хостинг.", "Checks the domain for malicious URLs and malware hosting.")} /><strong>{urlhaus?.status ?? "unknown"}</strong><p>{urlhaus?.note ?? t(locale, "Нет данных.", "No data.")}</p></div>
                          <div className="provider-card"><LabelWithHint label="Cisco Talos" hint={t(locale, "Репутация домена через Cisco Talos, если настроен источник.", "Domain reputation through Cisco Talos when a source is configured.")} /><strong>{talos?.status ?? "unknown"}</strong><p>{talos?.note ?? t(locale, "Нет данных.", "No data.")}</p></div>
                          <div className="provider-card"><LabelWithHint label="Lumen" hint={t(locale, "Юридические notice-сигналы и жалобы по домену.", "Legal notice signals and complaints associated with the domain.")} /><strong>{String(report.lumen.total_notices)}</strong><p>{report.lumen.note ?? t(locale, "Уведомлений не найдено.", "No notices found.")}</p></div>
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
                          <div><LabelWithHint label="Risk score" hint={t(locale, "Итоговая оценка риска от 0 до 100 на основе всех проверок.", "Final risk score from 0 to 100 based on all checks.")} /><strong>{report.risk_score}</strong></div>
                          <div><LabelWithHint label="Runtime" hint={t(locale, "Сводка по очереди, scheduler и сетевой стратегии текущего инстанса.", "Summary of queue, scheduler, and network strategy for the current instance.")} /><strong>{runtime ? `${runtime.max_parallel_jobs} / ${runtime.watch_scheduler_poll_seconds}s` : "..."}</strong></div>
                          <div><LabelWithHint label="Email auth" hint={t(locale, "Состояние SPF, DKIM и DMARC, которое влияет на доверие и почтовую репутацию домена.", "Status of SPF, DKIM, and DMARC, which influences domain trust and mail reputation.")} /><strong>{`SPF ${report.email_auth.spf}, DKIM ${report.email_auth.dkim}, DMARC ${report.email_auth.dmarc}`}</strong></div>
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
              <div><LabelWithHint label={t(locale, "HTTP стратегия", "HTTP strategy")} hint={t(locale, "Сколько прокси подряд пробуется и разрешён ли прямой запрос без прокси.", "How many proxies are tried in sequence and whether direct requests without a proxy are allowed.")} /><strong>{runtime ? `${runtime.proxy_attempts_per_request} / ${providerStateLabel(locale, runtime.direct_http_fallback)}` : "..."}</strong></div>
              <div><LabelWithHint label={t(locale, "Очередь", "Queue")} hint={t(locale, "Параллельность задач и лимит создания новых проверок в минуту.", "Parallel job capacity and creation rate limit per minute.")} /><strong>{runtime ? `${runtime.max_parallel_jobs} | ${runtime.check_rate_limit_per_minute}/min` : "..."}</strong></div>
              <div><LabelWithHint label="Watchlist" hint={t(locale, "Количество активных доменов в мониторинге и интервал опроса планировщика.", "Number of active monitored domains and the scheduler polling interval.")} /><strong>{runtime ? `${runtime.active_watchlist} | ${runtime.watch_scheduler_poll_seconds}s` : "..."}</strong></div>
              <div><LabelWithHint label={t(locale, "Провайдеры", "Providers")} hint={t(locale, "Какие внешние сервисы сейчас реально включены глобальными ключами.", "Which external services are currently enabled by global credentials.")} /><strong>{runtime ? Object.entries(runtime.configured_providers).filter(([, enabled]) => enabled).map(([key]) => key).join(", ") || t(locale, "ключи не настроены", "no keys configured") : "..."}</strong></div>
            </div>
          </div>

          <div className="card">
            <h2>{t(locale, "Смена пароля", "Change password")}</h2>
            <form className="form" onSubmit={(event) => void handlePasswordChange(event)}>
              <label>
                <span>{t(locale, "Текущий пароль", "Current password")}</span>
                <input type="password" value={passwordForm.current_password} onChange={(event) => setPasswordForm((current) => ({ ...current, current_password: event.target.value }))} />
              </label>
              <label>
                <span>{t(locale, "Новый пароль", "New password")}</span>
                <input type="password" value={passwordForm.new_password} onChange={(event) => setPasswordForm((current) => ({ ...current, new_password: event.target.value }))} />
              </label>
              <button type="submit" disabled={passwordSaving}>
                {passwordSaving ? t(locale, "Сохранение...", "Saving...") : t(locale, "Обновить пароль", "Update password")}
              </button>
            </form>
          </div>

          <div className="card">
            <h2>{t(locale, "Экспорт", "Exports")}</h2>
            <div className="actions">
              <a className={`button-link ${!exportJobId ? "disabled-link" : ""}`} href={exportJobId ? api.reportUrl(exportJobId, "json") : "#"}>JSON</a>
              <a className={`button-link ghost-link ${!exportJobId ? "disabled-link" : ""}`} href={exportJobId ? api.reportUrl(exportJobId, "csv") : "#"}>CSV</a>
              <a className={`button-link ghost-link ${!exportJobId ? "disabled-link" : ""}`} href={exportJobId ? api.reportUrl(exportJobId, "pdf") : "#"}>PDF</a>
            </div>
            {!exportJobId ? <p className="muted">{t(locale, "Экспорт появится после первой проверки.", "Exports become available after the first scan.")}</p> : null}
          </div>
        </div>
      </section>

      <section className="card nav-card">
        <div className="tabs">
          <button type="button" className={activeTab === "guide" ? "tab-button active" : "tab-button"} onClick={() => setActiveTab("guide")}>{t(locale, "Справка", "Guide")}</button>
          <button type="button" className={activeTab === "history" ? "tab-button active" : "tab-button"} onClick={() => setActiveTab("history")}>{t(locale, "История", "History")}</button>
          <button type="button" className={activeTab === "watchlist" ? "tab-button active" : "tab-button"} onClick={() => setActiveTab("watchlist")}>Watchlist</button>
          <button type="button" className={activeTab === "proxies" ? "tab-button active" : "tab-button"} onClick={() => setActiveTab("proxies")}>Proxies</button>
          <button type="button" className={activeTab === "webhooks" ? "tab-button active" : "tab-button"} onClick={() => setActiveTab("webhooks")}>Webhooks</button>
          {session.user.role === "owner" || session.user.role === "admin" ? <button type="button" className={activeTab === "admin" ? "tab-button active" : "tab-button"} onClick={() => setActiveTab("admin")}>{t(locale, "Админка", "Admin")}</button> : null}
        </div>

        {activeTab === "guide" ? (
          <div className="tab-panel">
            <div className="card-head">
              <div>
                <h2>{t(locale, "Как читать результаты", "How to read results")}</h2>
                <p className="muted">{t(locale, "Здесь краткая памятка по risk score, статусам, runtime и webhook-уведомлениям.", "A quick guide for risk score, statuses, runtime, and webhook notifications.")}</p>
              </div>
            </div>
            <div className="provider-grid">
              <article className="provider-card">
                <h3>{t(locale, "Risk score", "Risk score")}</h3>
                <p>{t(locale, "0 означает чистую проверку. Чем выше число, тем больше негативных сигналов собрано из DNSBL, Safe Browsing, Lumen, email-auth и внешних reputation-провайдеров.", "0 means a clean result. Higher values mean more negative signals from DNSBL, Safe Browsing, Lumen, email auth, and external reputation providers.")}</p>
                <p>{t(locale, "Обычно 1-59 это риск, от 60 и выше это уже высокий риск и чаще всего листинг.", "Usually 1-59 means warning risk, while 60+ means high risk and often a listed result.")}</p>
              </article>
              <article className="provider-card">
                <h3>{t(locale, "Статусы", "Statuses")}</h3>
                <p>{t(locale, "Чисто: негативных совпадений нет.", "Clean: no negative matches were found.")}</p>
                <p>{t(locale, "Риск: есть косвенные или неполные сигналы, но без явного жёсткого листинга.", "Warning: there are indirect or partial signals, but no hard listing was found.")}</p>
                <p>{t(locale, "В листинге: есть DNSBL-листинг или серьёзный провайдерский сигнал вроде malware/phishing.", "Listed: there is a DNSBL listing or a serious provider signal such as malware or phishing.")}</p>
              </article>
              <article className="provider-card">
                <h3>Runtime</h3>
                <p>{t(locale, "HTTP стратегия: сколько прокси пробуется подряд и разрешён ли прямой запрос без прокси.", "HTTP strategy: how many proxies are tried per request and whether direct fallback is allowed.")}</p>
                <p>{t(locale, "Очередь: сколько задач можно выполнять параллельно и какой лимит на создание новых проверок в минуту.", "Queue: how many jobs can run in parallel and what creation rate limit is allowed per minute.")}</p>
                <p>{t(locale, "Watchlist: сколько активных доменов мониторится и как часто планировщик их перепроверяет.", "Watchlist: how many active domains are monitored and how often the scheduler rechecks them.")}</p>
              </article>
              <article className="provider-card">
                <h3>Webhooks</h3>
                <p>{t(locale, "Webhook отправляет HTTP-уведомление на твой URL после завершения или ошибки проверки.", "A webhook sends an HTTP notification to your URL when a check completes or fails.")}</p>
                <p>{t(locale, "Это нужно, если ты хочешь получать результаты во внешний сервис, CRM, Telegram-бота или свой backend.", "Use it when you want to deliver results into an external service, CRM, Telegram bot, or your own backend.")}</p>
              </article>
            </div>
          </div>
        ) : null}

        {activeTab === "history" ? (
          <div className="tab-panel">
            <div className="card-head">
              <div>
                <h2>{t(locale, "История проверок", "Check history")}</h2>
              </div>
              <div className="actions">
                <button type="button" onClick={() => exportHistoryJson(filteredHistory)}>{t(locale, "Экспорт JSON", "Export JSON")}</button>
                <button type="button" className="ghost-button" onClick={() => exportHistoryCsv(filteredHistory)}>{t(locale, "Экспорт CSV", "Export CSV")}</button>
              </div>
            </div>
            <form className="filter-row history-filter-row" onSubmit={(event) => { event.preventDefault(); void loadHistory("", historyDays); }}>
              <label><span>{t(locale, "Домен", "Domain")}</span><input value={historyDomain} onChange={(event) => setHistoryDomain(event.target.value)} /></label>
              <label><span>{t(locale, "Период, дней", "Period, days")}</span><input type="number" min="1" max="365" value={historyDays} onChange={(event) => setHistoryDays(event.target.value)} /></label>
              <label><span>{t(locale, "Количество", "Limit")}</span><input type="number" min="1" max="500" value={historyLimit} onChange={(event) => setHistoryLimit(event.target.value)} /></label>
              <label><span>{t(locale, "Статус", "Status")}</span><select value={historyStatusFilter} onChange={(event) => setHistoryStatusFilter(event.target.value)}><option value="all">{t(locale, "Все", "All")}</option><option value="listed">{t(locale, "В листинге", "Listed")}</option><option value="warning">{t(locale, "Риск", "Warning")}</option><option value="clean">{t(locale, "Чисто", "Clean")}</option></select></label>
              <button type="submit">{historyLoading ? t(locale, "Загрузка...", "Loading...") : t(locale, "Обновить", "Refresh")}</button>
            </form>
            <div className="history-list">
              {filteredHistory.map((item) => (
                <article key={`${item.job_id}-${item.domain}-${item.checked_at}`} className="history-row">
                  <div><strong>{item.domain}</strong><p>{formatDate(locale, item.checked_at)} | job {item.job_id}</p></div>
                  <div className="history-metrics">
                    <StatusBadge status={item.overall_status} locale={locale} />
                    <strong>{item.risk_score}</strong>
                    <button type="button" onClick={() => void openHistoryDetails(item)}>{t(locale, "Подробнее", "Details")}</button>
                    <button type="button" className="ghost-button" onClick={() => void removeHistoryItem(item.id)}>{t(locale, "Удалить", "Delete")}</button>
                  </div>
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
            <div className="card-head"><div><h2>Webhooks <Hint text={t(locale, "Webhook отправляет POST-запрос на внешний URL после завершения или ошибки проверки.", "A webhook sends a POST request to an external URL when a scan completes or fails.")} /></h2></div></div>
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
              <div className="card-head">
                <div>
                  <h2>{t(locale, "Создать пользователя", "Create user")}</h2>
                </div>
              </div>
              <form className="form provider-form" onSubmit={(event) => void handleAdminUserCreate(event)}>
                <label>
                  <span>{t(locale, "Логин", "Username")}</span>
                  <input value={adminUserForm.username} onChange={(event) => setAdminUserForm((current) => ({ ...current, username: event.target.value }))} />
                </label>
                <label>
                  <span>{t(locale, "Пароль", "Password")}</span>
                  <input type="password" value={adminUserForm.password} onChange={(event) => setAdminUserForm((current) => ({ ...current, password: event.target.value }))} />
                </label>
                <label>
                  <span>{t(locale, "Роль", "Role")}</span>
                  <select value={adminUserForm.role} onChange={(event) => setAdminUserForm((current) => ({ ...current, role: event.target.value }))}>
                    <option value="user">user</option>
                    <option value="admin">admin</option>
                  </select>
                </label>
                <label>
                  <span>{t(locale, "Статус", "Status")}</span>
                  <select value={adminUserForm.status} onChange={(event) => setAdminUserForm((current) => ({ ...current, status: event.target.value }))}>
                    <option value="approved">{t(locale, "Активен", "Approved")}</option>
                    <option value="pending">{t(locale, "Ожидает", "Pending")}</option>
                    <option value="blocked">{t(locale, "Заблокирован", "Blocked")}</option>
                  </select>
                </label>
                <label>
                  <span>{t(locale, "Язык", "Language")}</span>
                  <select value={adminUserForm.language} onChange={(event) => setAdminUserForm((current) => ({ ...current, language: event.target.value as Locale }))}>
                    <option value="ru">RU</option>
                    <option value="en">EN</option>
                  </select>
                </label>
                <label>
                  <span>{t(locale, "Лимит доменов", "Domain limit")}</span>
                  <input value={adminUserForm.max_domains} onChange={(event) => setAdminUserForm((current) => ({ ...current, max_domains: event.target.value }))} placeholder="1000" />
                </label>
                <button type="submit" disabled={adminUserSaving}>
                  {adminUserSaving ? t(locale, "Создание...", "Creating...") : t(locale, "Создать пользователя", "Create user")}
                </button>
              </form>
            </div>
            <div className="card inset-card">
              <div className="card-head">
                <div>
                  <h2>{t(locale, "Сбросить пароль пользователя", "Reset user password")}</h2>
                </div>
              </div>
              <form className="form provider-form" onSubmit={(event) => void handleAdminPasswordReset(event)}>
                <label>
                  <span>{t(locale, "Пользователь", "User")}</span>
                  <select value={adminPasswordForm.user_id} onChange={(event) => setAdminPasswordForm((current) => ({ ...current, user_id: event.target.value }))}>
                    <option value="">{t(locale, "Выбери пользователя", "Select user")}</option>
                    {adminUsers.map((item) => (
                      <option key={item.id} value={String(item.id)}>
                        {item.username}
                      </option>
                    ))}
                  </select>
                </label>
                <label>
                  <span>{t(locale, "Новый пароль", "New password")}</span>
                  <input type="password" value={adminPasswordForm.password} onChange={(event) => setAdminPasswordForm((current) => ({ ...current, password: event.target.value }))} />
                </label>
                <button type="submit" disabled={adminPasswordSaving}>
                  {adminPasswordSaving ? t(locale, "Сохранение...", "Saving...") : t(locale, "Обновить пароль", "Update password")}
                </button>
              </form>
            </div>
            <div className="card inset-card">
              <div className="card-head"><div><h2>{t(locale, "Глобальные API и интеграции", "Global APIs and integrations")}</h2></div></div>
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
              <div className="card-head">
                <div>
                  <h2>{t(locale, "Пользователи", "Users")}</h2>
                </div>
                <label className="admin-filter">
                  <span>{t(locale, "Поиск", "Search")}</span>
                  <input value={adminUserFilter} onChange={(event) => setAdminUserFilter(event.target.value)} />
                </label>
              </div>
              <div className="table-wrap">
                <table>
                  <thead><tr><th>{t(locale, "Логин", "Username")}</th><th>{t(locale, "Роль", "Role")}</th><th>{t(locale, "Статус", "Status")}</th><th>{t(locale, "Показатели", "Metrics")}</th><th>{t(locale, "Действия", "Actions")}</th></tr></thead>
                  <tbody>
                    {filteredAdminUsers.map((user) => (
                      <tr key={user.id}>
                        <td><strong>{user.username}</strong><div className="table-subtext">{formatDate(locale, user.created_at)}</div></td>
                        <td>{user.role}</td>
                        <td><StatusBadge status={user.status} locale={locale} /></td>
                        <td>{`${user.job_count} jobs | ${user.proxy_count} proxy | ${user.watch_count} watch`}</td>
                        <td>
                          <div className="actions">
                            {user.status === "pending" ? (
                              <button type="button" onClick={() => void updateUserStatus(user.id, { status: "approved", status_message: null })}>
                                {t(locale, "Подтвердить", "Approve")}
                              </button>
                            ) : null}
                            {user.role === "user" ? (
                              <button type="button" onClick={() => void updateUserStatus(user.id, { role: "admin" })}>
                                {t(locale, "Сделать admin", "Make admin")}
                              </button>
                            ) : user.role === "admin" ? (
                              <button type="button" className="ghost-button" onClick={() => void updateUserStatus(user.id, { role: "user" })}>
                                {t(locale, "Сделать user", "Make user")}
                              </button>
                            ) : null}
                            {user.status !== "blocked" ? (
                              <button type="button" className="ghost-button" onClick={() => void updateUserStatus(user.id, { status: "blocked", status_message: t(locale, "Аккаунт заблокирован администратором.", "Account was blocked by an administrator.") })}>
                                {t(locale, "Заблокировать", "Block")}
                              </button>
                            ) : (
                              <button type="button" onClick={() => void updateUserStatus(user.id, { status: "approved", status_message: null })}>
                                {t(locale, "Разблокировать", "Unblock")}
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        ) : null}
      </section>
      </>
      )}
    </div>
  );
}
