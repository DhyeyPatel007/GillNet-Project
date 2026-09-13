import { createFileRoute } from "@tanstack/react-router";
import { useState, useEffect, useCallback, useRef, type ReactNode } from "react";
import {
  AlertTriangle,
  Anchor,
  Bug,
  ChevronDown,
  Clock3,
  Database,
  Globe2,
  KeyRound,
  Lightbulb,
  Link2,
  LockKeyhole,
  Menu,
  Search,
  Shield,
  X,
  LogOut,
  Home,
  CheckCircle2,
  AlertCircle,
  RefreshCw,
  Sun,
  Moon,
  UploadCloud,
  FileText,
  Image as ImageIcon,
  Trash2,
  ExternalLink,
  ShieldAlert,
  HelpCircle,
  Copy,
  Check,
  ArrowUpRight,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import globeImage from "@/assets/security-globe.png";
import { useAuth } from "@/lib/auth-context";
import {
  api,
  type UrlScanResult,
  type PhishingScanResult,
  type PasswordScanResult,
  type ScanRecord,
  type HistoryStats,
} from "@/lib/api";

export const Route = createFileRoute("/dashboard")({
  head: () => ({
    meta: [
      { title: "GillNet AI | Security Dashboard" },
      {
        name: "description",
        content:
          "Scan suspicious links, messages, screenshots, and passwords with the GillNet AI security dashboard.",
      },
      { property: "og:title", content: "GillNet AI | Security Dashboard" },
      {
        property: "og:description",
        content: "Scan suspicious links, messages, screenshots, and passwords with GillNet AI.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: DashboardPage,
});

function DashboardPage() {
  const { user, logout } = useAuth();
  const [menuOpen, setMenuOpen] = useState(false);
  const [profileDropdownOpen, setProfileDropdownOpen] = useState(false);

  // Theme state: dark (default) or light
  const [theme, setTheme] = useState<"dark" | "light">(() => {
    if (typeof window !== "undefined") {
      const saved = localStorage.getItem("gillnet_dash_theme");
      if (saved === "light" || saved === "dark") return saved;
    }
    return "dark";
  });

  const toggleTheme = () => {
    const next = theme === "dark" ? "light" : "dark";
    setTheme(next);
    if (typeof window !== "undefined") {
      localStorage.setItem("gillnet_dash_theme", next);
    }
  };

  // Security stats state
  const [stats, setStats] = useState<HistoryStats>({
    totalScans: 7,
    safeCount: 4,
    suspiciousCount: 1,
    highRiskCount: 2,
    averageRiskScore: 40.4,
  });

  // Recent activity state
  const [historyRecords, setHistoryRecords] = useState<ScanRecord[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);

  // 1. Link Scanner state
  const [scanInput, setScanInput] = useState("");
  const [scanning, setScanning] = useState(false);
  const [scanError, setScanError] = useState<string | null>(null);
  const [urlScanResult, setUrlScanResult] = useState<UrlScanResult | null>(null);

  // 2. New Phishing Scanner state (Screenshot & Text)
  const [phishingTab, setPhishingTab] = useState<"screenshot" | "text">("screenshot");
  const [phishingText, setPhishingText] = useState("");
  const [phishingImageBase64, setPhishingImageBase64] = useState<string | null>(null);
  const [phishingImageFileName, setPhishingImageFileName] = useState<string>("");
  const [phishingImageSize, setPhishingImageSize] = useState<string>("");
  const [phishingScanning, setPhishingScanning] = useState(false);
  const [phishingError, setPhishingError] = useState<string | null>(null);
  const [phishingResult, setPhishingResult] = useState<PhishingScanResult | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // 3. Password checker state
  const [passwordInput, setPasswordInput] = useState("");
  const [checkingPassword, setCheckingPassword] = useState(false);
  const [passwordResult, setPasswordResult] = useState<PasswordScanResult | null>(null);

  // Fetch stats and history
  const refreshData = useCallback(async () => {
    setHistoryLoading(true);
    try {
      const [newStats, newHistory] = await Promise.all([
        api.history.getStats().catch(() => null),
        api.history.get(user?.id).catch(() => []),
      ]);
      if (newStats) setStats(newStats);
      if (newHistory && newHistory.length > 0) setHistoryRecords(newHistory);
    } catch (err) {
      console.warn("Error refreshing dashboard data:", err);
    } finally {
      setHistoryLoading(false);
    }
  }, [user?.id]);

  useEffect(() => {
    refreshData();
  }, [refreshData]);

  // Execute Link Threat Scan with strict URL-only validation
  const handleLinkScan = async (overrideValue?: string) => {
    const val = (overrideValue ?? scanInput).trim();
    if (!val) {
      setScanError("Please enter a URL to scan.");
      return;
    }

    // Strict URL validation: Reject paragraphs, sentences, or text with spaces
    const hasWhitespace = /\s/.test(val);
    const looksLikeSentence = val.split(" ").length > 1 || val.includes("\n") || val.length > 250;
    const isUrlPattern =
      /^https?:\/\//i.test(val) ||
      (!hasWhitespace && (val.includes(".") || val.includes("localhost") || /^\d+\.\d+\.\d+\.\d+/.test(val)));

    if (hasWhitespace || looksLikeSentence || !isUrlPattern) {
      setScanError(
        "Link Scanner only accepts URLs (e.g. https://example.com or domain.com). To scan sentences, messages, emails, or screenshots, please use the Phishing Scanner below."
      );
      setUrlScanResult(null);
      return;
    }

    setScanError(null);
    setScanning(true);
    setUrlScanResult(null);

    try {
      const res = await api.urlScan.analyze(val, user?.id);
      setUrlScanResult(res);
      refreshData();
    } catch (err: any) {
      setScanError(err.message || "Failed to analyze URL. Check backend connection.");
    } finally {
      setScanning(false);
    }
  };

  // Image Upload Handler for Phishing Scanner
  const handleFileSelect = (file: File) => {
    if (!file.type.startsWith("image/")) {
      setPhishingError("Please upload a valid image file (PNG, JPG, JPEG, WEBP).");
      return;
    }
    setPhishingError(null);
    setPhishingImageFileName(file.name);
    setPhishingImageSize(`${Math.round(file.size / 1024)} KB`);

    const reader = new FileReader();
    reader.onload = (e) => {
      const b64 = e.target?.result as string;
      setPhishingImageBase64(b64);
    };
    reader.readAsDataURL(file);
  };

  const removeImage = () => {
    setPhishingImageBase64(null);
    setPhishingImageFileName("");
    setPhishingImageSize("");
    if (fileInputRef.current) fileInputRef.current.value = "";
  };

  // Execute Phishing Scanner (Screenshot or Text)
  const handlePhishingScan = async () => {
    setPhishingError(null);
    setPhishingResult(null);

    if (phishingTab === "screenshot") {
      if (!phishingImageBase64) {
        setPhishingError("Please upload or drag-and-drop a screenshot to analyze.");
        return;
      }
      setPhishingScanning(true);
      try {
        const res = await api.phishing.analyzeImage(phishingImageBase64, phishingImageFileName, user?.id);
        setPhishingResult(res);
        refreshData();
      } catch (err: any) {
        setPhishingError(err.message || "Failed to analyze screenshot.");
      } finally {
        setPhishingScanning(false);
      }
    } else {
      if (!phishingText.trim()) {
        setPhishingError("Please paste email or message text to analyze.");
        return;
      }
      setPhishingScanning(true);
      try {
        const res = await api.phishing.analyzeText(phishingText.trim(), user?.id);
        setPhishingResult(res);
        refreshData();
      } catch (err: any) {
        setPhishingError(err.message || "Failed to analyze message text.");
      } finally {
        setPhishingScanning(false);
      }
    }
  };

  // Quick text samples for testing Phishing Scanner
  const loadPhishingSample = (type: "paypal" | "bank" | "lottery") => {
    setPhishingTab("text");
    if (type === "paypal") {
      setPhishingText(
        "URGENT ALERT: Your PayPal account has been limited due to suspicious login attempts. You must confirm your identity within 24 hours at http://paypal-security-update-account.com or your wallet balance will be permanently frozen. Do not ignore this final notice."
      );
    } else if (type === "bank") {
      setPhishingText(
        "Chase Bank Security Notification: Unauthorized wire transaction of $1,840 detected on your checking account. If you did not authorize this, call immediately or verify your card number and PIN at http://chase-fraud-defense.net to block the transaction."
      );
    } else {
      setPhishingText(
        "Congratulations! Dear Customer, you have won $50,000 in the International Crypto Lottery Giveaway! To claim your prize, provide your login credentials and full legal name to claim-reward@crypto-prize.org."
      );
    }
    setPhishingError(null);
  };

  // Execute password check
  const handlePasswordCheck = async () => {
    if (!passwordInput) {
      setPasswordResult(null);
      return;
    }

    setCheckingPassword(true);
    try {
      const res = await api.passwordScan.analyze(passwordInput);
      setPasswordResult(res);
      refreshData();
    } catch (err) {
      console.warn("Password scan error:", err);
    } finally {
      setCheckingPassword(false);
    }
  };

  const displayName = user?.name || (user?.email ? user.email.split("@")[0] : "Analyst");
  const userInitial = displayName.charAt(0).toUpperCase();

  const navItems = [
    { label: "Dashboard", href: "#top" },
    { label: "Link Scan", href: "#scan" },
    { label: "Phishing Scan", href: "#phishing" },
    { label: "Password Check", href: "#password" },
    { label: "Recent Activity", href: "#history" },
    { label: "Security Intel", href: "#security" },
  ];

  return (
    <div
      id="top"
      className={`dashboard-container ${
        theme === "light" ? "dashboard-light" : "dashboard-dark"
      } min-h-screen bg-shell text-foreground font-sans selection:bg-safe selection:text-black`}
    >
      <main className="min-h-screen bg-shell p-0 min-[1400px]:p-0">
        <div className="relative mx-auto min-h-screen w-full overflow-hidden border-2 border-frame bg-background min-[1400px]:h-[1080px] min-[1400px]:min-h-0 min-[1400px]:max-w-[1440px] min-[1400px]:rounded-[25px]">
          {/* MOBILE BACKDROP OVERLAY */}
          {menuOpen && (
            <div
              className="fixed inset-0 z-40 bg-black/70 backdrop-blur-sm min-[1400px]:hidden transition-opacity"
              onClick={() => setMenuOpen(false)}
              aria-hidden="true"
            />
          )}

          {/* SIDEBAR */}
          <aside
            id="dashboard-sidebar"
            className={`${
              menuOpen ? "translate-x-0" : "-translate-x-full"
            } dashboard-sidebar fixed inset-y-0 left-0 z-50 w-[240px] flex flex-col bg-sidebar-panel border-r border-frame transition-transform duration-200 ease-in-out min-[1400px]:translate-x-0 min-[1400px]:absolute min-[1400px]:inset-y-0 min-[1400px]:flex min-[1400px]:w-[226px]`}
          >
            <div className="flex h-[99px] items-center justify-between border-b border-sidebar-line px-6">
              <span className="font-brand text-[28px] leading-none text-ink">
                GillNet AI
              </span>
              <button
                className="grid size-9 place-items-center rounded-lg border border-sidebar-line/30 text-ink hover:bg-ink/10 transition-colors min-[1400px]:hidden cursor-pointer"
                onClick={() => setMenuOpen(false)}
                aria-label="Close menu"
              >
                <X className="size-5" />
              </button>
            </div>

            <nav className="flex flex-col items-center gap-7 pt-[48px]" aria-label="Main navigation">
              {navItems.map((item) => (
                <a
                  key={item.label}
                  href={item.href}
                  className="font-brand text-xl leading-[26px] text-ink transition-opacity hover:opacity-55"
                  onClick={() => setMenuOpen(false)}
                >
                  {item.label}
                </a>
              ))}

              <div className="mt-6 pt-6 border-t border-sidebar-line/20 w-4/5 flex flex-col items-center gap-3">
                {/* Mobile Theme Toggle */}
                <button
                  onClick={toggleTheme}
                  className="flex items-center gap-2 rounded-full border border-sidebar-line/30 bg-ink/5 px-4 py-1.5 text-xs font-medium text-ink hover:bg-ink/10 transition-colors cursor-pointer"
                >
                  {theme === "dark" ? <Sun className="size-3.5 text-warning" /> : <Moon className="size-3.5 text-violet" />}
                  <span>{theme === "dark" ? "Light Mode" : "Dark Mode"}</span>
                </button>

                <a
                  href="/"
                  className="flex items-center gap-2 font-brand text-base text-ink/80 hover:text-ink transition-all"
                >
                  <Home className="size-4" />
                  Landing Page
                </a>

                <button
                  onClick={() => {
                    logout();
                    window.location.href = "/";
                  }}
                  className="flex items-center gap-2 font-brand text-base text-destructive hover:opacity-80 transition-all cursor-pointer"
                >
                  <LogOut className="size-4" />
                  Sign Out
                </button>
              </div>
            </nav>
          </aside>

          {/* HEADER */}
          <header className="grid grid-cols-[auto_1fr_auto] items-center gap-x-3 gap-y-3 px-5 py-4 min-[700px]:flex min-[700px]:h-[106px] min-[700px]:py-0 min-[1400px]:absolute min-[1400px]:left-[286px] min-[1400px]:top-0 min-[1400px]:w-[1116px] min-[1400px]:px-0">
            {/* VISIBLE & STYLED HAMBURGER BUTTON */}
            <button
              onClick={() => setMenuOpen((prev) => !prev)}
              className="grid size-11 shrink-0 place-items-center rounded-xl border-2 border-frame bg-surface text-foreground shadow-md hover:bg-surface/80 transition-all cursor-pointer min-[1400px]:hidden"
              aria-label="Toggle navigation menu"
            >
              <Menu className="size-5" />
            </button>

            {/* Header Quick Scan Bar */}
            <div className="order-3 col-span-3 min-w-0 min-[700px]:order-none min-[700px]:col-span-1 min-[700px]:flex-1 min-[1400px]:w-[680px] min-[1400px]:flex-none">
              <div className="relative min-w-0">
                <div className="grid min-h-[52px] grid-cols-[auto_minmax(0,1fr)_auto] items-center overflow-hidden rounded-[28px] border-2 border-frame bg-background pl-4 sm:h-[50px] sm:rounded-[40px] sm:pl-5 shadow-sm">
                  <Search className="size-5 shrink-0 text-foreground/60" />
                  <input
                    aria-label="Quick scan URL"
                    type="text"
                    value={scanInput}
                    onChange={(e) => {
                      setScanInput(e.target.value);
                      setScanError(null);
                    }}
                    onKeyDown={(e) => e.key === "Enter" && handleLinkScan()}
                    placeholder="Enter URL to scan (e.g. https://google.com)..."
                    className="w-full min-w-0 bg-transparent px-3 font-sans text-foreground text-sm sm:text-base outline-none placeholder:text-foreground/40 sm:px-4"
                  />
                  <Button
                    onClick={() => handleLinkScan()}
                    disabled={scanning}
                    className="h-[48px] w-[105px] shrink-0 rounded-[28px] bg-primary p-0 font-normal text-primary-foreground hover:bg-primary/90 sm:h-[50px] sm:w-28 sm:rounded-[40px] text-sm sm:text-base cursor-pointer"
                  >
                    {scanning ? "Scanning..." : "Scan URL"}
                  </Button>
                </div>
              </div>
            </div>

            {/* Right Controls: Theme Toggle & Profile Dropdown */}
            <div className="order-2 ml-auto flex items-center gap-3 min-[700px]:order-none">
              {/* Theme Toggle Button */}
              <button
                onClick={toggleTheme}
                className="flex items-center gap-1.5 rounded-xl border-2 border-frame bg-surface px-3 py-2 text-xs font-medium text-foreground hover:bg-surface/80 transition-all cursor-pointer shadow-sm"
                title={`Switch to ${theme === "dark" ? "Light" : "Dark"} Mode`}
              >
                {theme === "dark" ? (
                  <>
                    <Sun className="size-4 text-warning" />
                    <span className="hidden sm:inline">Light</span>
                  </>
                ) : (
                  <>
                    <Moon className="size-4 text-violet" />
                    <span className="hidden sm:inline">Dark</span>
                  </>
                )}
              </button>

              {/* Profile Menu */}
              <div className="relative">
                <button
                  onClick={() => setProfileDropdownOpen((prev) => !prev)}
                  className="flex items-center gap-2.5 cursor-pointer group"
                  aria-label="User profile menu"
                >
                  <div className="grid size-[48px] shrink-0 place-items-center overflow-hidden rounded-full bg-primary font-sans text-xl font-medium text-primary-foreground shadow-sm">
                    {user?.picture ? (
                      <img src={user.picture} alt={displayName} className="size-full object-cover" />
                    ) : (
                      userInitial
                    )}
                  </div>
                  <span className="hidden font-sans text-lg font-medium text-bright min-[700px]:block group-hover:underline">
                    {displayName}
                  </span>
                  <ChevronDown className="hidden size-4 text-bright min-[700px]:block transition-transform duration-200" />
                </button>

                {/* Profile Dropdown */}
                {profileDropdownOpen && (
                  <div className="absolute right-0 top-14 z-50 w-56 rounded-2xl border border-frame bg-shell p-2 shadow-2xl backdrop-blur-md">
                    <div className="px-3 py-2 border-b border-frame/30">
                      <p className="font-sans text-sm font-semibold text-bright">{displayName}</p>
                      <p className="font-sans text-xs text-muted-foreground truncate">{user?.email || "Signed in"}</p>
                    </div>
                    <a
                      href="/"
                      className="flex items-center gap-2.5 rounded-xl px-3 py-2 text-sm text-bright hover:bg-surface transition-colors mt-1"
                    >
                      <Home className="size-4" />
                      Back to Landing Page
                    </a>
                    <button
                      onClick={() => {
                        logout();
                        window.location.href = "/";
                      }}
                      className="flex w-full items-center gap-2.5 rounded-xl px-3 py-2 text-sm text-destructive hover:bg-destructive/10 transition-colors cursor-pointer"
                    >
                      <LogOut className="size-4" />
                      Sign Out
                    </button>
                  </div>
                )}
              </div>
            </div>
          </header>

          {/* MAIN GRID BODY */}
          <div className="grid gap-6 px-4 pb-8 sm:px-6 min-[1400px]:absolute min-[1400px]:left-[272px] min-[1400px]:top-[130px] min-[1400px]:bottom-6 min-[1400px]:overflow-y-auto min-[1400px]:pr-3 min-[1400px]:grid-cols-[740px_368px] min-[1400px]:gap-5 min-[1400px]:p-0">
            {/* LEFT COLUMN: Main scanning & tools */}
            <div className="min-w-0 space-y-4">
              {/* Welcome Banner */}
              <section className="relative min-h-[148px] overflow-hidden sm:h-[125px] sm:min-h-0 rounded-[25px] border border-frame bg-shell/40">
                <div className="relative z-10 max-w-full px-6 py-4 sm:absolute sm:left-7 sm:top-[14px] sm:p-0 z-10 max-w-[calc(100%-230px)]">
                  <h1 className="whitespace-nowrap font-display text-2xl leading-[36px] sm:text-[28px] text-bright">
                    Welcome back, {displayName}
                  </h1>
                  <p className="mt-0.5 max-w-[420px] font-sans text-xs leading-5 text-muted-foreground sm:text-sm sm:leading-6">
                    Multi-layer AI cybersecurity: Scan links, detect screenshot & text phishing, verify passwords.
                  </p>
                </div>
                <div className="absolute -top-px right-[8px] hidden h-[125px] w-[216px] overflow-hidden rounded-[25px] border border-frame/40 bg-background sm:block">
                  <img
                    src={globeImage}
                    alt="Digital security globe"
                    className="h-full w-full object-cover object-right opacity-85 mix-blend-screen"
                  />
                </div>
              </section>

              {/* Statistics Metrics Bar */}
              <section
                className="grid grid-cols-1 gap-2.5 py-1 min-[430px]:grid-cols-2 min-[1400px]:flex min-[1400px]:h-[95px] min-[1400px]:grid-cols-none min-[1400px]:items-center min-[1400px]:gap-2.5 min-[1400px]:py-0"
                aria-label="Security statistics"
              >
                <Metric
                  icon={<Search />}
                  title="Total Scans"
                  value={String(stats.totalScans)}
                  suffix="/100"
                  tone="neutral"
                  width="w-full min-[1400px]:w-[195px]"
                  progress
                  progressPct={Math.min(stats.totalScans, 100)}
                />
                <Metric
                  icon={<Shield />}
                  title="Safe Score"
                  value={String(stats.safeCount)}
                  tone="safe"
                  width="w-full min-[1400px]:w-[175px]"
                />
                <Metric
                  icon={<AlertTriangle />}
                  title="Threats"
                  value={String(stats.suspiciousCount + stats.highRiskCount)}
                  tone="danger"
                  width="w-full min-[1400px]:w-[160px]"
                />
                <Metric
                  icon={<Database />}
                  title="Detected"
                  value={String(stats.highRiskCount)}
                  tone="violet"
                  width="w-full min-[1400px]:w-[160px]"
                />
              </section>

              {/* 1. LINK SCANNER PANEL */}
              <section id="scan" className="rounded-[25px] border border-frame bg-shell/40 px-[24px] py-[18px]">
                <PanelTitle
                  icon={<Link2 />}
                  title="Link Scanner"
                  subtitle="Verify domain authenticity, SSL encryption, and structural features via retrained Random Forest ML model."
                />

                <div className="mt-3">
                  <div className="grid min-h-[52px] grid-cols-[auto_minmax(0,1fr)_auto] items-center overflow-hidden rounded-[28px] border-2 border-frame bg-background pl-4 sm:h-[48px] sm:rounded-[40px] sm:pl-5">
                    <Link2 className="size-4 shrink-0 text-foreground/70" />
                    <input
                      aria-label="URL to scan"
                      type="text"
                      value={scanInput}
                      onChange={(e) => {
                        setScanInput(e.target.value);
                        setScanError(null);
                      }}
                      onKeyDown={(e) => e.key === "Enter" && handleLinkScan()}
                      placeholder="Enter target URL (e.g. https://paypal.com)..."
                      className="w-full min-w-0 bg-transparent px-3 font-sans text-xs sm:text-sm text-foreground outline-none placeholder:text-foreground/40 sm:px-4"
                    />
                    <Button
                      onClick={() => handleLinkScan()}
                      disabled={scanning}
                      className="h-[46px] w-[105px] shrink-0 rounded-[28px] bg-primary p-0 font-normal text-primary-foreground hover:bg-primary/90 sm:h-[48px] sm:w-28 sm:rounded-[40px] text-xs sm:text-sm cursor-pointer"
                    >
                      {scanning ? "Scanning..." : "Scan URL"}
                    </Button>
                  </div>
                </div>

                {/* Error Banner when paragraph/sentence is entered */}
                {scanError && (
                  <div className="mt-2.5 flex items-start gap-2 rounded-xl border border-destructive/30 bg-destructive/10 p-2.5 text-xs text-destructive font-sans">
                    <AlertCircle className="size-4 shrink-0 mt-0.5" />
                    <div className="flex-1">
                      <p className="font-semibold">URL Validation Error</p>
                      <p className="mt-0.5">{scanError}</p>
                    </div>
                  </div>
                )}

                {/* URL Scan Result */}
                {urlScanResult && (
                  <div className="mt-3.5 rounded-2xl border-2 border-frame/70 bg-surface p-4 space-y-3.5 animate-fadeIn shadow-md">
                    {/* Header banner */}
                    <div className="flex flex-wrap items-center justify-between gap-2 border-b border-frame/40 pb-3">
                      <div className="flex items-center gap-2.5">
                        <span
                          className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-bold ${
                            urlScanResult.prediction === "SAFE"
                              ? "bg-safe text-black"
                              : "bg-destructive text-white"
                          }`}
                        >
                          {urlScanResult.prediction === "SAFE" ? <CheckCircle2 className="size-3.5" /> : <AlertTriangle className="size-3.5" />}
                          {urlScanResult.prediction}
                        </span>
                        <span className="text-xs text-muted-foreground truncate max-w-[280px] sm:max-w-[400px] font-mono">
                          {urlScanResult.url}
                        </span>
                      </div>
                      <div className="font-numeric text-xs sm:text-sm font-bold text-bright">
                        Risk Score:{" "}
                        <span className={urlScanResult.riskScore > 50 ? "text-destructive" : "text-safe"}>
                          {urlScanResult.riskScore}/100
                        </span>
                        <span className="text-xs text-muted-foreground font-normal ml-2">
                          ({urlScanResult.confidence}% confidence · {urlScanResult.model})
                        </span>
                      </div>
                    </div>

                    {/* Threat Score Progress Bar */}
                    <div className="space-y-1">
                      <div className="flex justify-between text-[11px] text-muted-foreground font-medium">
                        <span>Safe (0)</span>
                        <span>Suspicious (50)</span>
                        <span>Malicious / Phishing (100)</span>
                      </div>
                      <div className="h-2 w-full rounded-full bg-track overflow-hidden">
                        <div
                          className={`h-full transition-all duration-700 ${
                            urlScanResult.riskScore >= 60
                              ? "bg-destructive"
                              : urlScanResult.riskScore >= 40
                              ? "bg-warning"
                              : "bg-safe"
                          }`}
                          style={{ width: `${urlScanResult.riskScore}%` }}
                        />
                      </div>
                    </div>

                    {/* Multi-Vector Threat Indicators */}
                    <div className="space-y-2 text-xs">
                      <p className="font-semibold text-bright flex items-center gap-1.5">
                        <Shield className={`size-3.5 ${urlScanResult.prediction === "SAFE" ? "text-safe" : "text-destructive"}`} />
                        Threat Intelligence Reasoning ({urlScanResult.reasons.length} Heuristic Vectors):
                      </p>
                      <ul className="space-y-1.5">
                        {urlScanResult.reasons.map((r, i) => {
                          const tagMatch = r.match(/^\[(.*?)\]\s*(.*)$/);
                          const categoryTag = tagMatch ? tagMatch[1] : null;
                          const reasonText = tagMatch ? tagMatch[2] : r;
                          return (
                            <li
                              key={i}
                              className={`flex items-start gap-2.5 rounded-xl border p-2.5 text-bright ${
                                urlScanResult.prediction === "SAFE"
                                  ? "border-frame/30 bg-background/40"
                                  : "border-destructive/30 bg-destructive/10"
                              }`}
                            >
                              <span
                                className={`flex size-4 shrink-0 items-center justify-center rounded-full text-[10px] font-bold mt-0.5 ${
                                  urlScanResult.prediction === "SAFE" ? "bg-safe text-black" : "bg-destructive text-white"
                                }`}
                              >
                                {i + 1}
                              </span>
                              <div className="flex-1 space-y-0.5">
                                {categoryTag && (
                                  <span className="inline-block rounded px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wider bg-background/70 border border-frame/40 text-muted-foreground mr-1.5">
                                    {categoryTag}
                                  </span>
                                )}
                                <span className="text-xs leading-snug">{reasonText}</span>
                              </div>
                            </li>
                          );
                        })}
                      </ul>
                    </div>

                    {/* Actionable Recommendation Card */}
                    <div
                      className={`rounded-xl border p-3 text-xs leading-relaxed ${
                        urlScanResult.prediction === "SAFE"
                          ? "border-safe/30 bg-safe/10 text-bright"
                          : "border-destructive/30 bg-destructive/10 text-destructive"
                      }`}
                    >
                      <p className="font-semibold flex items-center gap-1.5 mb-1">
                        {urlScanResult.prediction === "SAFE" ? (
                          <CheckCircle2 className="size-4 text-safe shrink-0" />
                        ) : (
                          <AlertTriangle className="size-4 text-destructive shrink-0" />
                        )}
                        <span>AI Security Assessment & Guidance</span>
                      </p>
                      <p className="font-sans leading-relaxed text-bright/90">
                        {urlScanResult.recommendation}
                      </p>
                    </div>
                  </div>
                )}
              </section>

              {/* 2. NEW SERVICE: PHISHING SCANNER (SCREENSHOT & TEXT) */}
              <section id="phishing" className="rounded-[25px] border-2 border-frame bg-shell/50 px-[24px] py-[20px] shadow-sm">
                <div className="flex flex-wrap items-center justify-between gap-3 border-b border-frame/40 pb-3">
                  <PanelTitle
                    icon={<ShieldAlert className="text-warning" />}
                    title="Phishing Scanner"
                    subtitle="Detect deceptive screenshots, spoofed interfaces, and scam text messages."
                  />
                  {/* Mode switcher pills */}
                  <div className="flex rounded-full border border-frame bg-background p-1 text-xs">
                    <button
                      onClick={() => {
                        setPhishingTab("screenshot");
                        setPhishingError(null);
                      }}
                      className={`flex items-center gap-1.5 rounded-full px-3 py-1 font-medium transition-colors cursor-pointer ${
                        phishingTab === "screenshot" ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:text-bright"
                      }`}
                    >
                      <ImageIcon className="size-3.5" />
                      Screenshot Upload
                    </button>
                    <button
                      onClick={() => {
                        setPhishingTab("text");
                        setPhishingError(null);
                      }}
                      className={`flex items-center gap-1.5 rounded-full px-3 py-1 font-medium transition-colors cursor-pointer ${
                        phishingTab === "text" ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:text-bright"
                      }`}
                    >
                      <FileText className="size-3.5" />
                      Text / Email Body
                    </button>
                  </div>
                </div>

                {/* SCREENSHOT MODE */}
                {phishingTab === "screenshot" ? (
                  <div className="mt-4 space-y-3">
                    <input
                      ref={fileInputRef}
                      type="file"
                      accept="image/*"
                      className="hidden"
                      onChange={(e) => {
                        if (e.target.files && e.target.files[0]) {
                          handleFileSelect(e.target.files[0]);
                        }
                      }}
                    />

                    {phishingImageBase64 ? (
                      <div className="flex flex-col sm:flex-row items-center gap-4 rounded-2xl border border-frame bg-surface p-3.5">
                        <div className="relative size-24 shrink-0 overflow-hidden rounded-xl border border-frame bg-background">
                          <img
                            src={phishingImageBase64}
                            alt="Screenshot preview"
                            className="size-full object-cover"
                          />
                        </div>
                        <div className="min-w-0 flex-1 space-y-1 text-center sm:text-left">
                          <p className="font-medium text-sm text-bright truncate">{phishingImageFileName}</p>
                          <p className="text-xs text-muted-foreground">Size: {phishingImageSize}</p>
                          <p className="text-xs text-safe flex items-center justify-center sm:justify-start gap-1">
                            <CheckCircle2 className="size-3.5" /> Ready for AI visual analysis
                          </p>
                        </div>
                        <div className="flex gap-2">
                          <Button
                            variant="destructive"
                            size="sm"
                            onClick={removeImage}
                            className="gap-1 rounded-xl text-xs cursor-pointer"
                          >
                            <Trash2 className="size-3.5" /> Remove
                          </Button>
                          <Button
                            size="sm"
                            disabled={phishingScanning}
                            onClick={handlePhishingScan}
                            className="rounded-xl bg-primary text-primary-foreground text-xs cursor-pointer"
                          >
                            {phishingScanning ? "Analyzing..." : "Analyze Screenshot"}
                          </Button>
                        </div>
                      </div>
                    ) : (
                      <div
                        onDragOver={(e) => e.preventDefault()}
                        onDrop={(e) => {
                          e.preventDefault();
                          if (e.dataTransfer.files && e.dataTransfer.files[0]) {
                            handleFileSelect(e.dataTransfer.files[0]);
                          }
                        }}
                        onClick={() => fileInputRef.current?.click()}
                        className="group flex flex-col items-center justify-center rounded-2xl border-2 border-dashed border-frame/70 bg-surface/40 p-6 text-center hover:border-primary/60 hover:bg-surface transition-all cursor-pointer"
                      >
                        <div className="grid size-12 place-items-center rounded-full border border-frame bg-background group-hover:scale-105 transition-transform">
                          <UploadCloud className="size-6 text-foreground/70" />
                        </div>
                        <p className="mt-3 text-sm font-semibold text-bright">
                          Drag & drop suspicious screenshot or click to browse
                        </p>
                        <p className="mt-1 text-xs text-muted-foreground">
                          Supports PNG, JPG, WEBP (e.g. fake login dialog, urgent banking alert, invoice email)
                        </p>
                      </div>
                    )}
                  </div>
                ) : (
                  /* TEXT MODE */
                  <div className="mt-4 space-y-3">
                    <textarea
                      rows={4}
                      value={phishingText}
                      onChange={(e) => {
                        setPhishingText(e.target.value);
                        setPhishingError(null);
                      }}
                      placeholder="Paste suspicious email text, SMS scam message, or WhatsApp prompt here..."
                      className="w-full rounded-2xl border-2 border-frame bg-background p-3.5 font-sans text-xs sm:text-sm text-foreground outline-none placeholder:text-foreground/40 focus:border-primary transition-colors resize-none"
                    />

                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex flex-wrap items-center gap-1.5">
                        <span className="text-xs text-muted-foreground">Quick test samples:</span>
                        <button
                          onClick={() => loadPhishingSample("paypal")}
                          className="rounded-lg border border-frame bg-surface px-2.5 py-1 text-[11px] text-bright hover:bg-surface/80 transition-colors cursor-pointer"
                        >
                          PayPal Impersonation
                        </button>
                        <button
                          onClick={() => loadPhishingSample("bank")}
                          className="rounded-lg border border-frame bg-surface px-2.5 py-1 text-[11px] text-bright hover:bg-surface/80 transition-colors cursor-pointer"
                        >
                          Bank Fraud SMS
                        </button>
                        <button
                          onClick={() => loadPhishingSample("lottery")}
                          className="rounded-lg border border-frame bg-surface px-2.5 py-1 text-[11px] text-bright hover:bg-surface/80 transition-colors cursor-pointer"
                        >
                          Lottery Lure
                        </button>
                      </div>

                      <Button
                        disabled={phishingScanning}
                        onClick={handlePhishingScan}
                        className="rounded-xl bg-primary text-primary-foreground text-xs sm:text-sm h-9 px-5 cursor-pointer"
                      >
                        {phishingScanning ? "Analyzing..." : "Analyze Text"}
                      </Button>
                    </div>
                  </div>
                )}

                {/* Phishing Error message */}
                {phishingError && (
                  <p className="mt-2.5 text-xs text-destructive font-sans flex items-center gap-1.5">
                    <AlertCircle className="size-3.5" />
                    {phishingError}
                  </p>
                )}

                {/* DETAILED PHISHING THREAT REPORT */}
                {phishingResult && (
                  <div className="mt-4 rounded-2xl border-2 border-frame bg-surface p-4 space-y-3.5 animate-fadeIn shadow-md">
                    {/* Header banner */}
                    <div className="flex flex-wrap items-center justify-between gap-2 border-b border-frame/40 pb-3">
                      <div className="flex items-center gap-2.5">
                        <span
                          className={`inline-flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-bold ${
                            phishingResult.threatLevel === "PHISHING"
                              ? "bg-destructive text-white"
                              : phishingResult.threatLevel === "SUSPICIOUS"
                              ? "bg-warning text-black"
                              : "bg-safe text-black"
                          }`}
                        >
                          {phishingResult.threatLevel === "PHISHING" ? (
                            <AlertTriangle className="size-3.5" />
                          ) : phishingResult.threatLevel === "SUSPICIOUS" ? (
                            <HelpCircle className="size-3.5" />
                          ) : (
                            <CheckCircle2 className="size-3.5" />
                          )}
                          {phishingResult.threatLevel}
                        </span>
                        <span className="text-sm font-semibold text-bright">Detailed Threat Report</span>
                      </div>

                      <div className="font-numeric text-xs sm:text-sm font-bold text-bright">
                        Threat Score:{" "}
                        <span
                          className={
                            phishingResult.riskScore >= 70
                              ? "text-destructive"
                              : phishingResult.riskScore >= 40
                              ? "text-warning"
                              : "text-safe"
                          }
                        >
                          {phishingResult.riskScore}/100
                        </span>{" "}
                        <span className="text-xs text-muted-foreground font-normal">
                          ({phishingResult.confidence}% confidence)
                        </span>
                      </div>
                    </div>

                    {/* Threat Score Progress Bar */}
                    <div className="space-y-1">
                      <div className="flex justify-between text-[11px] text-muted-foreground font-medium">
                        <span>Low Risk (0)</span>
                        <span>Medium (50)</span>
                        <span>Severe Threat (100)</span>
                      </div>
                      <div className="h-2 w-full rounded-full bg-track overflow-hidden">
                        <div
                          className={`h-full transition-all duration-700 ${
                            phishingResult.riskScore >= 70
                              ? "bg-destructive"
                              : phishingResult.riskScore >= 40
                              ? "bg-warning"
                              : "bg-safe"
                          }`}
                          style={{ width: `${phishingResult.riskScore}%` }}
                        />
                      </div>
                    </div>

                    {/* Executive Summary */}
                    <p className="text-xs sm:text-sm text-bright leading-relaxed bg-background/50 rounded-xl p-3 border border-frame/40">
                      {phishingResult.summary}
                    </p>

                    {/* Feature Analysis Grid */}
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 text-xs">
                      <div className="rounded-xl border border-frame/40 bg-background/40 p-2.5">
                        <span className="text-muted-foreground">Brand Target:</span>
                        <p className="font-semibold text-bright mt-0.5">{phishingResult.brandImpersonated || "None Identified"}</p>
                      </div>

                      <div className="rounded-xl border border-frame/40 bg-background/40 p-2.5">
                        <span className="text-muted-foreground">Credential Harvesting:</span>
                        <p
                          className={`font-semibold mt-0.5 ${
                            phishingResult.credentialHarvesting ? "text-destructive font-bold" : "text-safe"
                          }`}
                        >
                          {phishingResult.credentialHarvesting ? "CRITICAL: Credential Harvesting Detected" : "None Detected"}
                        </p>
                      </div>
                    </div>

                    {/* Visual OCR Text Preview */}
                    {phishingResult.extractedText && (
                      <div className="rounded-xl border border-frame/40 bg-background/40 p-2.5 space-y-1.5 text-xs">
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-bright flex items-center gap-1.5">
                            <FileText className="size-3.5 text-primary" /> Visual Text Extracted (RapidOCR)
                          </span>
                          <span className="text-[10px] text-muted-foreground font-mono">
                            {phishingResult.extractedText.split("\n").filter(Boolean).length} lines detected
                          </span>
                        </div>
                        <pre className="max-h-28 overflow-y-auto whitespace-pre-wrap rounded-lg border border-frame/30 bg-surface/80 p-2 font-mono text-[11px] text-bright leading-relaxed">
                          {phishingResult.extractedText}
                        </pre>
                      </div>
                    )}

                    {/* Extracted Embedded URLs Section */}
                    {phishingResult.extractedUrls && phishingResult.extractedUrls.length > 0 && (
                      <div className="space-y-1.5 rounded-xl border border-frame/40 bg-background/40 p-2.5 text-xs">
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-bright flex items-center gap-1.5">
                            <Link2 className="size-3.5 text-primary" /> Embedded Hyperlink Inspection ({phishingResult.extractedUrls.length} found):
                          </span>
                          <span className="text-[10px] text-muted-foreground font-mono">
                            Decisive threat factor
                          </span>
                        </div>
                        <div className="space-y-1 mt-1">
                          {phishingResult.extractedUrls.map((url, i) => (
                            <div key={i} className="flex items-center justify-between gap-2 rounded-lg bg-surface/70 px-2.5 py-1.5 border border-frame/30">
                              <span className="font-mono text-[11px] text-bright truncate max-w-[420px]">{url}</span>
                              <button
                                onClick={() => {
                                  setScanInput(url);
                                  handleLinkScan(url);
                                  const el = document.getElementById("scan");
                                  if (el) el.scrollIntoView({ behavior: "smooth" });
                                }}
                                className="text-[10px] text-primary hover:underline shrink-0 flex items-center gap-1 cursor-pointer font-medium"
                              >
                                Deep Inspect <ArrowUpRight className="size-3" />
                              </button>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Detected Indicators & Why Flagged */}
                    {phishingResult.indicators.length > 0 && (
                      <div className="space-y-2 text-xs">
                        <p className="font-semibold text-bright flex items-center gap-1.5">
                          {phishingResult.threatLevel === "PHISHING" ? (
                            <AlertTriangle className="size-3.5 text-destructive" />
                          ) : (
                            <ShieldAlert className="size-3.5 text-warning" />
                          )}
                          Why This Was Flagged ({phishingResult.indicators.length} Threat Indicators):
                        </p>
                        <ul className="space-y-1.5">
                          {phishingResult.indicators.map((ind, i) => {
                            const tagMatch = ind.match(/^\[(.*?)\]\s*(.*)$/);
                            const categoryTag = tagMatch ? tagMatch[1] : null;
                            const reasonText = tagMatch ? tagMatch[2] : ind;
                            return (
                              <li
                                key={i}
                                className={`flex items-start gap-2.5 rounded-xl border p-2.5 text-bright ${
                                  phishingResult.threatLevel === "PHISHING"
                                    ? "border-destructive/30 bg-destructive/10"
                                    : phishingResult.threatLevel === "SUSPICIOUS"
                                    ? "border-warning/30 bg-warning/10"
                                    : "border-frame/30 bg-background/40"
                                }`}
                              >
                                <span
                                  className={`flex size-4 shrink-0 items-center justify-center rounded-full text-[10px] font-bold mt-0.5 ${
                                    phishingResult.threatLevel === "PHISHING"
                                      ? "bg-destructive text-white"
                                      : phishingResult.threatLevel === "SUSPICIOUS"
                                      ? "bg-warning text-black"
                                      : "bg-safe text-black"
                                  }`}
                                >
                                  {i + 1}
                                </span>
                                <div className="flex-1 space-y-0.5">
                                  {categoryTag && (
                                    <span className="inline-block rounded px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wider bg-background/70 border border-frame/40 text-muted-foreground mr-1.5">
                                      {categoryTag}
                                    </span>
                                  )}
                                  <span className="leading-snug text-xs font-sans">{reasonText}</span>
                                </div>
                              </li>
                            );
                          })}
                        </ul>
                      </div>
                    )}

                    {/* Actionable Recommendations */}
                    {phishingResult.recommendations.length > 0 && (
                      <div className="space-y-1.5 text-xs border-t border-frame/30 pt-2.5">
                        <p className="font-semibold text-safe">Actionable Defense Steps:</p>
                        <ul className="space-y-1 text-muted-foreground">
                          {phishingResult.recommendations.map((rec, i) => (
                            <li key={i} className="flex items-start gap-2">
                              <CheckCircle2 className="size-3.5 text-safe mt-0.5 shrink-0" />
                              <span>{rec}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                )}
              </section>

              {/* 3. PASSWORD CHECKER PANEL */}
              <section id="password" className="rounded-[25px] border border-frame bg-shell/40 px-[24px] py-[18px]">
                <PanelTitle
                  icon={<KeyRound />}
                  title="Password Checker"
                  subtitle="Zero-storage Shannon entropy evaluation. Passwords are never saved or logged."
                />

                <div className="mt-3">
                  <div className="grid min-h-[52px] grid-cols-[auto_minmax(0,1fr)_auto] items-center overflow-hidden rounded-[28px] border-2 border-frame bg-background pl-4 sm:h-[48px] sm:rounded-[40px] sm:pl-5">
                    <LockKeyhole className="size-4 shrink-0 text-foreground/70" />
                    <input
                      aria-label="Password to check"
                      type="password"
                      value={passwordInput}
                      onChange={(e) => setPasswordInput(e.target.value)}
                      onKeyDown={(e) => e.key === "Enter" && handlePasswordCheck()}
                      placeholder="Enter password to evaluate security strength..."
                      className="w-full min-w-0 bg-transparent px-3 font-sans text-xs sm:text-sm text-foreground outline-none placeholder:text-foreground/40 sm:px-4"
                    />
                    <Button
                      onClick={handlePasswordCheck}
                      disabled={checkingPassword}
                      className="h-[46px] w-[105px] shrink-0 rounded-[28px] bg-primary p-0 font-normal text-primary-foreground hover:bg-primary/90 sm:h-[48px] sm:w-28 sm:rounded-[40px] text-xs sm:text-sm cursor-pointer"
                    >
                      {checkingPassword ? "Testing..." : "Check"}
                    </Button>
                  </div>
                </div>

                {/* Strength Meter Bar */}
                <div className="mt-3 grid grid-cols-[auto_minmax(60px,1fr)_auto] items-center gap-x-3 font-sans text-xs leading-none text-muted-foreground">
                  <span className="shrink-0 font-medium text-bright">Strength :</span>
                  <div className="flex min-w-0 flex-1 gap-1.5 min-[1400px]:flex-none">
                    {[1, 2, 3, 4].map((seg) => {
                      let active = false;
                      let colorClass = "bg-progress/20";
                      const score = passwordResult?.score ?? (passwordInput.length > 0 ? 25 : 0);

                      if (score >= 80) {
                        active = seg <= 4;
                        colorClass = "bg-safe";
                      } else if (score >= 60) {
                        active = seg <= 3;
                        colorClass = "bg-safe-soft";
                      } else if (score >= 40) {
                        active = seg <= 2;
                        colorClass = "bg-warning";
                      } else if (score > 0) {
                        active = seg <= 1;
                        colorClass = "bg-destructive";
                      }

                      return (
                        <i
                          key={seg}
                          className={`h-1.5 min-w-0 flex-1 rounded-full transition-colors ${
                            active ? colorClass : "bg-track"
                          } min-[1400px]:w-[42px] min-[1400px]:flex-none`}
                        />
                      );
                    })}
                  </div>
                  <span
                    className={`shrink-0 font-medium ${
                      (passwordResult?.score ?? 0) >= 70
                        ? "text-safe"
                        : (passwordResult?.score ?? 0) >= 40
                        ? "text-warning"
                        : "text-destructive"
                    } min-[1400px]:ml-auto min-[1400px]:mr-3`}
                  >
                    {passwordResult ? passwordResult.strength.replace("_", " ") : passwordInput ? "Evaluating" : "None"}
                  </span>
                </div>

                {passwordResult && (
                  <div className="mt-3 rounded-2xl border border-frame/60 bg-surface p-3.5 space-y-3 text-xs animate-fadeIn shadow-sm">
                    {/* Top metrics row */}
                    <div className="flex flex-wrap items-center justify-between gap-2 border-b border-frame/30 pb-2.5">
                      <div className="flex items-center gap-2">
                        <span className="font-semibold text-bright">Estimated Crack Resistance:</span>
                        <span className="font-bold text-safe">{passwordResult.estimatedCrackTime}</span>
                      </div>
                      <div className="font-numeric text-bright font-medium">
                        Shannon Entropy: <span className="text-safe font-bold">{passwordResult.entropy} bits</span>
                        <span className="text-[11px] text-muted-foreground ml-1.5">({passwordResult.score}/100 security score)</span>
                      </div>
                    </div>

                    {/* Passed criteria pills */}
                    {passwordResult.passedCriteria && passwordResult.passedCriteria.length > 0 && (
                      <div className="space-y-1.5">
                        <span className="text-[11px] font-semibold text-bright flex items-center gap-1.5">
                          <CheckCircle2 className="size-3 text-safe" /> Verified Password Strengths:
                        </span>
                        <div className="flex flex-wrap gap-1.5">
                          {passwordResult.passedCriteria.map((crit, i) => (
                            <span
                              key={i}
                              className="inline-flex items-center gap-1 rounded-full border border-safe/30 bg-safe/10 px-2.5 py-0.5 text-[11px] font-medium text-safe"
                            >
                              <Check className="size-3" />
                              {crit}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Suggestions & pattern analysis */}
                    {passwordResult.suggestions && passwordResult.suggestions.length > 0 && (
                      <div className="space-y-1.5 border-t border-frame/30 pt-2.5">
                        <span className="text-[11px] font-semibold text-bright flex items-center gap-1.5">
                          <Lightbulb className="size-3 text-warning" /> Security Hardening & Vulnerability Guidance:
                        </span>
                        <ul className="space-y-1">
                          {passwordResult.suggestions.map((sug, i) => {
                            const tagMatch = sug.match(/^\[(.*?)\]\s*(.*)$/);
                            const tag = tagMatch ? tagMatch[1] : null;
                            const desc = tagMatch ? tagMatch[2] : sug;
                            const isCritical = tag && (tag.includes("Critical") || tag.includes("Immediate"));
                            const isPattern = tag && tag.includes("Pattern");
                            return (
                              <li
                                key={i}
                                className={`flex items-start gap-2 rounded-lg border p-2 text-[11px] ${
                                  isCritical
                                    ? "border-destructive/30 bg-destructive/10 text-destructive"
                                    : isPattern
                                    ? "border-warning/30 bg-warning/10 text-warning"
                                    : "border-frame/30 bg-background/40 text-muted-foreground"
                                }`}
                              >
                                {isCritical ? (
                                  <AlertCircle className="size-3.5 shrink-0 mt-0.5 text-destructive" />
                                ) : isPattern ? (
                                  <AlertTriangle className="size-3.5 shrink-0 mt-0.5 text-warning" />
                                ) : (
                                  <Lightbulb className="size-3.5 shrink-0 mt-0.5 text-warning" />
                                )}
                                <div className="flex-1">
                                  {tag && (
                                    <span className="font-bold uppercase tracking-wider text-[10px] mr-1.5">
                                      [{tag}]
                                    </span>
                                  )}
                                  <span className="text-bright/90">{desc}</span>
                                </div>
                              </li>
                            );
                          })}
                        </ul>
                      </div>
                    )}
                  </div>
                )}
              </section>

              {/* 4. SECURITY OVERVIEW */}
              <section id="security" className="rounded-[25px] border border-frame bg-shell/40 px-[24px] py-[18px]">
                <PanelTitle
                  icon={<Shield />}
                  title="Security Overview"
                  subtitle="Our multi-layer platform continuously inspects emerging threats in real time."
                />
                <div className="mt-3 grid grid-cols-1 gap-2.5 min-[430px]:grid-cols-2 sm:grid-cols-4">
                  <Feature
                    icon={<Bug />}
                    title="Malware Detection"
                    text="Detect payload delivery URLs & deceptive endpoints."
                  />
                  <Feature
                    icon={<Anchor />}
                    title="Phishing Protection"
                    text="Identify brand spoofing & domain impersonation."
                  />
                  <Feature
                    icon={<LockKeyhole />}
                    title="Password Analysis"
                    text="Zero-storage Shannon entropy evaluation."
                  />
                  <Feature
                    icon={<Globe2 />}
                    title="Real-time Threat Intel"
                    text="Continuous ML calibration against emerging attacks."
                  />
                </div>
              </section>
            </div>

            {/* RIGHT COLUMN: History & Tips */}
            <div className="space-y-4">
              {/* RECENT ACTIVITY */}
              <section id="history" className="rounded-[25px] border border-frame bg-shell/40 px-[20px] py-[18px]">
                <div className="flex h-[38px] items-start justify-between border-b border-divider px-1">
                  <h2 className="flex items-center gap-2 font-display text-base sm:text-lg text-bright">
                    <Clock3 className="size-4 text-safe" />
                    Recent Activity
                  </h2>
                  <button
                    onClick={refreshData}
                    disabled={historyLoading}
                    className="flex items-center gap-1 text-xs text-muted-foreground hover:text-bright transition-colors cursor-pointer"
                    title="Refresh history"
                  >
                    <RefreshCw className={`size-3 ${historyLoading ? "animate-spin" : ""}`} />
                    Refresh
                  </button>
                </div>

                <div className="divide-y divide-frame/20 mt-1 max-h-[380px] overflow-y-auto pr-1">
                  {historyRecords.length === 0 ? (
                    <p className="py-6 text-center text-xs text-muted-foreground">No recent scans recorded.</p>
                  ) : (
                    historyRecords.slice(0, 8).map((rec, index) => {
                      const isSafe = rec.result?.toUpperCase() === "SAFE" || rec.riskScore < 40;
                      const isSuspicious = rec.result?.toUpperCase() === "SUSPICIOUS" || (rec.riskScore >= 40 && rec.riskScore < 70);
                      const statusLabel = isSafe ? "safe" : isSuspicious ? "suspicious" : "phishing";

                      const date = new Date(rec.timestamp);
                      const timeString = isNaN(date.getTime())
                        ? "recently"
                        : date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });

                      return (
                        <div
                          key={rec.id || index}
                          className="grid h-[42px] grid-cols-[20px_1fr_auto] items-center gap-2 px-1 font-sans text-[11px]"
                        >
                          <span className="grid size-[20px] place-items-center rounded-[5px] bg-activity text-bright">
                            {rec.scanType === "PASSWORD" ? (
                              <KeyRound className="size-3" />
                            ) : rec.scanType?.includes("IMAGE") ? (
                              <ImageIcon className="size-3" />
                            ) : (
                              <Link2 className="size-3" />
                            )}
                          </span>
                          <span className="truncate text-bright/90 font-medium" title={rec.sanitizedTarget}>
                            {rec.sanitizedTarget.replace(/^https?:\/\//i, "").replace(/\/$/, "")}
                          </span>
                          <span className="flex items-center gap-1.5 justify-end">
                            <i
                              className={`size-1.5 rounded-full ${
                                isSafe ? "bg-safe" : isSuspicious ? "bg-warning" : "bg-destructive"
                              }`}
                            />
                            <b
                              className={`font-normal uppercase text-[10px] ${
                                isSafe ? "text-safe" : isSuspicious ? "text-warning" : "text-destructive"
                              }`}
                            >
                              {statusLabel}
                            </b>
                            <small className="text-right text-[9px] text-muted-foreground w-12 truncate">
                              {timeString}
                            </small>
                          </span>
                        </div>
                      );
                    })
                  )}
                </div>
              </section>

              {/* TIPS FOR A SAFER INTERNET */}
              <section className="rounded-[25px] border border-frame bg-shell/40 px-[20px] py-[18px]">
                <h2 className="flex h-[34px] items-start gap-2 border-b border-divider px-1 font-display text-base sm:text-lg text-bright">
                  <Lightbulb className="size-4 text-warning" />
                  Tips for a safer Internet
                </h2>
                <ul className="mt-3 space-y-2.5 px-2 font-sans text-[11px] text-bright/85">
                  {[
                    "Don't click on unverified links or urgent email prompts.",
                    "Upload suspicious email screenshots to the Phishing Scanner.",
                    "Use unique passwords with length > 14 characters.",
                    "Be vigilant about lookalike domains (e.g. paypa1.com).",
                  ].map((tip) => (
                    <li key={tip} className="flex items-start gap-2 leading-snug">
                      <span className="size-[6px] shrink-0 rounded-full bg-safe mt-1" />
                      <span>{tip}</span>
                    </li>
                  ))}
                </ul>
              </section>

              {/* QUOTE SECTION */}
              <section className="flex min-h-[125px] items-center rounded-[25px] border border-frame bg-shell/40 px-5 py-3">
                <div className="grid size-14 shrink-0 place-items-center rounded-full border border-frame/60 bg-icon text-bright">
                  <Shield className="size-7" />
                </div>
                <blockquote className="ml-3.5 min-w-0 flex-1 font-sans text-xs sm:text-sm leading-5 text-bright">
                  “Security is not a product, but a process.”
                  <footer className="mt-1 text-right font-serif text-[11px] italic text-muted-foreground">
                    – Bruce Schneier
                  </footer>
                </blockquote>
              </section>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}

function PanelTitle({ icon, title, subtitle }: { icon: ReactNode; title: string; subtitle: string }) {
  return (
    <div className="flex gap-2.5">
      <span className="mt-0.5 shrink-0 text-bright [&_svg]:size-5">{icon}</span>
      <div className="min-w-0">
        <h2 className="font-display text-lg sm:text-xl leading-6 text-bright">{title}</h2>
        <p className="mt-0.5 font-sans text-[11px] leading-4 text-muted-foreground">{subtitle}</p>
      </div>
    </div>
  );
}

function Metric({
  icon,
  title,
  value,
  suffix,
  tone,
  width,
  progress = false,
  progressPct = 0,
}: {
  icon: ReactNode;
  title: string;
  value: string;
  suffix?: string;
  tone: "neutral" | "safe" | "danger" | "violet";
  width: string;
  progress?: boolean;
  progressPct?: number;
}) {
  const toneClass = {
    neutral: "bg-neutral/60 text-bright",
    safe: "bg-safe-muted/60 text-safe",
    danger: "bg-danger-muted/60 text-destructive",
    violet: "bg-violet-muted/60 text-violet",
  }[tone];

  return (
    <article
      className={`relative flex h-[86px] shrink-0 items-center rounded-[25px] border border-frame bg-shell/40 px-[14px] ${width}`}
    >
      <span className={`grid size-[42px] shrink-0 place-items-center rounded-full border border-frame/60 ${toneClass} [&_svg]:size-4`}>
        {icon}
      </span>
      <div className="min-w-0 flex-1 text-center">
        <div className="font-sans text-xs leading-4 text-muted-foreground">{title}</div>
        <div className="font-numeric text-xl sm:text-2xl font-semibold leading-6 text-bright">
          {value}
          {suffix && <span className="text-xs font-normal text-muted-foreground">{suffix}</span>}
        </div>
        {progress && (
          <div className="absolute bottom-[6px] left-[62px] right-[14px] h-1 rounded-full bg-track overflow-hidden">
            <div
              className="h-full rounded-full bg-safe transition-all duration-500"
              style={{ width: `${progressPct}%` }}
            />
          </div>
        )}
      </div>
    </article>
  );
}

function Feature({ icon, title, text }: { icon: ReactNode; title: string; text: string }) {
  return (
    <article className="flex h-[78px] min-w-0 items-start gap-2 rounded-[20px] border border-frame bg-surface px-3 py-2.5">
      <span className="shrink-0 text-bright [&_svg]:size-4">{icon}</span>
      <div className="min-w-0">
        <h3 className="font-sans text-[11px] font-semibold text-bright leading-4">{title}</h3>
        <p className="mt-0.5 font-sans text-[9px] leading-3 text-muted-foreground">{text}</p>
      </div>
    </article>
  );
}
