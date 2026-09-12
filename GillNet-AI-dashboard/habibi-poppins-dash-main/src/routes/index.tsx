import { createFileRoute } from "@tanstack/react-router";
import { useState, type ReactNode } from "react";
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
} from "lucide-react";
import { Button } from "@/components/ui/button";
import globeImage from "@/assets/security-globe.png";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "GillNet AI | Security Dashboard" },
      { name: "description", content: "Scan suspicious links, messages, and passwords with the GillNet AI security dashboard." },
      { property: "og:title", content: "GillNet AI | Security Dashboard" },
      { property: "og:description", content: "Scan suspicious links, messages, and passwords with GillNet AI." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: Dashboard,
});

const activity = [
  ["google.com", "safe", "12 mins ago"],
  ["xyz-login.com", "phishing", "30 mins ago"],
  ["youtube.com", "safe", "1 hour ago"],
  ["fake-bank.com", "suspicious", "2 hours ago"],
  ["youtube.com", "malware", "4 hours ago"],
  ["microsoft.com", "safe", "10 hours ago"],
  ["cloude.ai", "safe", "1 day ago"],
] as const;

const navigation = ["Home", "Scan", "Password", "History", "Security", "Profile"];

function ScanField({ password = false, compact = false }: { password?: boolean; compact?: boolean }) {
  const [value, setValue] = useState("");
  const [message, setMessage] = useState("");
  const check = () => setMessage(value.trim() ? (password ? "Strong password" : "No immediate threats found") : "Enter something to check");

  return (
    <div className={`relative min-w-0 ${password ? "pb-6" : ""}`}>
      <div className="grid min-h-[56px] grid-cols-[auto_minmax(0,1fr)_auto] items-center overflow-hidden rounded-[28px] border-2 border-frame bg-background pl-4 sm:h-[53px] sm:rounded-[40px] sm:pl-5">
        {password ? <LockKeyhole className="size-5 shrink-0" /> : <Link2 className={compact ? "size-6 shrink-0" : "size-5 shrink-0"} />}
        <input
          aria-label={password ? "Password to check" : "URL or suspicious message"}
          type={password ? "password" : "text"}
          value={value}
          onChange={(event) => { setValue(event.target.value); setMessage(""); }}
          onKeyDown={(event) => event.key === "Enter" && check()}
          placeholder={password ? "Enter your password here..." : "Enter a URL or suspicious message..."}
          className={`w-full min-w-0 bg-transparent px-3 font-sans text-foreground outline-none placeholder:text-foreground sm:px-4 ${compact ? "text-base sm:text-xl" : "text-sm sm:text-base"}`}
        />
        <Button onClick={check} className={`h-[52px] w-[112px] shrink-0 rounded-[28px] bg-primary p-0 font-normal text-primary-foreground hover:bg-primary/90 sm:h-[53px] sm:w-32 sm:rounded-[40px] ${compact ? "text-base sm:text-xl" : "text-sm sm:text-base"}`}>
          {password ? "Check Now" : "Scan Now"}
        </Button>
      </div>
      {message && <p className="absolute bottom-0 left-6 font-sans text-xs leading-4 text-safe" role="status">{message}</p>}
    </div>
  );
}

function Dashboard() {
  const [menuOpen, setMenuOpen] = useState(false);

  return (
    <main className="min-h-screen bg-shell p-0 min-[1400px]:p-0">
      <div className="relative mx-auto min-h-screen w-full overflow-hidden border-2 border-frame bg-background min-[1400px]:h-[1040px] min-[1400px]:min-h-0 min-[1400px]:max-w-[1440px] min-[1400px]:rounded-[25px]">
        <aside className={`${menuOpen ? "flex" : "hidden"} fixed inset-y-0 left-0 z-40 w-[226px] flex-col bg-sidebar-panel min-[1400px]:absolute min-[1400px]:inset-y-0 min-[1400px]:flex`}>
          <div className="flex h-[99px] items-center justify-between border-b border-sidebar-line px-10">
            <span className="font-brand text-[32px] leading-none text-ink">GillNet AI</span>
            <Button variant="ghost" size="icon" className="min-[1400px]:hidden" onClick={() => setMenuOpen(false)} aria-label="Close menu"><X /></Button>
          </div>
          <nav className="flex flex-col items-center gap-11 pt-[72px]" aria-label="Main navigation">
            {navigation.map((item) => (
              <a key={item} href={`#${item.toLowerCase()}`} className="font-brand text-2xl leading-[29px] text-ink transition-opacity hover:opacity-55" onClick={() => setMenuOpen(false)}>{item}</a>
            ))}
          </nav>
        </aside>

        <header className="grid grid-cols-[auto_1fr] items-center gap-x-4 gap-y-3 px-5 py-4 min-[700px]:flex min-[700px]:h-[106px] min-[700px]:py-0 min-[1400px]:absolute min-[1400px]:left-[286px] min-[1400px]:top-0 min-[1400px]:w-[1116px] min-[1400px]:px-0">
          <Button variant="ghost" size="icon" className="min-[1400px]:hidden" onClick={() => setMenuOpen(true)} aria-label="Open menu"><Menu /></Button>
          <div className="order-3 col-span-2 min-w-0 min-[700px]:order-none min-[700px]:col-span-1 min-[700px]:flex-1 min-[1400px]:w-[740px] min-[1400px]:flex-none"><ScanField compact /></div>
          <div className="order-2 ml-auto flex items-center gap-3 min-[700px]:order-none">
            <div className="grid size-[55px] shrink-0 place-items-center rounded-full bg-primary font-sans text-2xl text-primary-foreground">M</div>
            <span className="hidden font-sans text-xl text-bright min-[700px]:block">Mayank</span>
            <ChevronDown className="hidden size-4 text-bright min-[700px]:block" />
          </div>
        </header>

        <div className="grid gap-6 px-4 pb-8 sm:px-6 min-[1400px]:absolute min-[1400px]:left-[272px] min-[1400px]:top-[160px] min-[1400px]:grid-cols-[740px_368px] min-[1400px]:gap-5 min-[1400px]:p-0">
          <div className="min-w-0">
            <section className="relative min-h-[156px] overflow-hidden sm:h-[132px] sm:min-h-0 rounded-[25px] border border-frame">
              <div className="relative z-10 max-w-full px-6 py-6 sm:absolute sm:left-8 sm:top-[18px] sm:p-0 z-10 max-w-[calc(100%-48px)]">
                <h1 className="whitespace-nowrap font-display text-2xl leading-[42px] sm:text-[32px]">Welcome back, Mayank</h1>
                <p className="mt-0 max-w-[349px] font-sans text-sm leading-5 text-muted-foreground sm:text-base sm:leading-6">Stay one step ahead. Scan, Secure, and<br className="hidden sm:block" /> stay safe with GillNet AI.</p>
              </div>
              <div className="absolute -top-px right-[8px] hidden h-[132px] w-[216px] overflow-hidden rounded-[25px] border border-ink bg-background sm:block">
                <img src={globeImage} alt="Digital security globe" className="h-full w-full object-cover object-right opacity-80 mix-blend-screen" />
              </div>
            </section>

            <section className="grid grid-cols-1 gap-3 py-5 min-[430px]:grid-cols-2 min-[1400px]:flex min-[1400px]:h-[136px] min-[1400px]:grid-cols-none min-[1400px]:items-center min-[1400px]:gap-3 min-[1400px]:py-0" aria-label="Security statistics">
              <Metric icon={<Search />} title="Total Scans" value="82" suffix="/100" tone="neutral" width="w-full min-[1400px]:w-[203px]" progress />
              <Metric icon={<Shield />} title="Safe Score" value="24" tone="safe" width="w-full min-[1400px]:w-[184px]" />
              <Metric icon={<AlertTriangle />} title="Threats" value="5" tone="danger" width="w-full min-[1400px]:w-[164px]" />
              <Metric icon={<Database />} title="Detected" value="3" tone="violet" width="w-full min-[1400px]:w-[164px]" />
            </section>

            <section id="scan" className="min-h-[178px] rounded-[25px] border border-frame px-[28px] pt-[20px]">
              <PanelTitle icon={<Search />} title="Quick threat Scan" subtitle="Enter a URL or paste a suspicious message to check for threats." />
              <div className="mt-[21px]"><ScanField /></div>
            </section>

            <section id="password" className="mt-5 min-h-[208px] rounded-[25px] border border-frame px-[28px] pt-[20px]">
              <PanelTitle icon={<KeyRound />} title="Password checker" subtitle="Check how strong your password is..." />
              <div className="mt-[20px]"><ScanField password /></div>
              <div className="mt-3 grid grid-cols-[auto_minmax(60px,1fr)_auto] items-center gap-x-3 font-sans text-[15px] leading-none text-muted-foreground">
                <span className="shrink-0">Strength :</span>
                <div className="flex min-w-0 flex-1 gap-1 min-[1400px]:flex-none">
                  <i className="h-1 min-w-0 flex-1 rounded-full bg-safe min-[1400px]:w-[38px] min-[1400px]:flex-none" /><i className="h-1 min-w-0 flex-1 rounded-full bg-safe min-[1400px]:w-[38px] min-[1400px]:flex-none" /><i className="h-1 min-w-0 flex-1 rounded-full bg-safe min-[1400px]:w-[38px] min-[1400px]:flex-none" /><i className="h-1 min-w-0 flex-1 rounded-full bg-progress min-[1400px]:w-[38px] min-[1400px]:flex-none" />
                </div>
                <span className="shrink-0 text-safe min-[1400px]:ml-auto min-[1400px]:mr-4">Strong</span>
              </div>
            </section>

            <section id="security" className="mt-5 min-h-[184px] rounded-[25px] border border-frame px-[29px] pb-6 pt-[20px] min-[1400px]:h-[184px]">
              <PanelTitle icon={<Shield />} title="Security Overview" subtitle="Our AI helps you stay protected in real time." />
              <div className="mt-4 grid grid-cols-1 gap-3 min-[430px]:grid-cols-2 sm:grid-cols-4">
                <Feature icon={<Bug />} title="Malware Detection" text="Detect malicious files and links." />
                <Feature icon={<Anchor />} title="Phishing Protection" text="Identify phishing attempts." />
                <Feature icon={<LockKeyhole />} title="Password Analysis" text="Check Password security and strength." />
                <Feature icon={<Globe2 />} title="Real time threat Intel" text="Stay up-to date with real world threats." />
              </div>
            </section>
          </div>

          <aside>
            <section id="history" className="min-h-[420px] rounded-[25px] border border-frame px-[25px] pt-[21px]">
              <div className="flex h-[41px] items-start justify-between border-b border-divider px-1">
                <h2 className="flex items-center gap-3 font-display text-xl"><Clock3 className="size-5" />Recent Activity</h2>
                <a href="#history" className="pt-1 font-sans text-sm">View all&nbsp; →</a>
              </div>
              <div>
                {activity.map(([domain, status, time], index) => (
                  <div key={`${domain}-${index}`} className="grid h-[46px] grid-cols-[21px_1fr_auto] items-center gap-3 px-1 font-sans text-[11px]">
                    <span className="grid size-[21px] place-items-center rounded-[5px] bg-activity"><Link2 className="size-3" /></span>
                    <span>{domain}</span>
                    <span className="grid grid-cols-[6px_62px_50px] items-center gap-1"><i className={`size-1 rounded-full ${status === "safe" ? "bg-safe" : status === "suspicious" ? "bg-warning" : "bg-destructive"}`} /><b className={`font-normal ${status === "safe" ? "text-safe" : status === "suspicious" ? "text-warning" : "text-destructive"}`}>{status}</b><small className="text-right text-[7px] text-foreground">{time}</small></span>
                  </div>
                ))}
              </div>
            </section>

            <section className="mt-5 min-h-[200px] rounded-[25px] border border-frame px-[25px] pt-[21px]">
              <h2 className="flex h-[38px] items-start gap-3 border-b border-divider px-1 font-display text-xl"><Lightbulb className="size-5" />Tips for a safer Internet</h2>
              <ul className="mt-[15px] space-y-[10px] px-3 font-sans text-[11px] text-bright">
                {["Don't click on suspicious links.", "Use strong and unique passwords.", "Be aware of phishing attempts.", "Keep your devices updated."].map(tip => <li key={tip} className="flex items-center gap-3"><span className="size-[7px] shrink-0 rounded-full bg-safe" />{tip}</li>)}
              </ul>
            </section>

            <section className="mt-5 flex min-h-[184px] items-center rounded-[25px] border border-frame px-[27px]">
              <div className="grid size-20 shrink-0 place-items-center rounded-full border border-frame/60 bg-icon"><Shield className="size-[43px]" /></div>
              <blockquote className="ml-5 min-w-0 flex-1 font-sans text-base leading-6 text-bright">“Security is not a process<br />but a process.”<footer className="mt-2 text-right font-sans text-[13px] italic">–Bruce Schneier</footer></blockquote>
            </section>
          </aside>
        </div>
      </div>
    </main>
  );
}

function PanelTitle({ icon, title, subtitle }: { icon: ReactNode; title: string; subtitle: string }) {
  return <div className="flex gap-3"><span className="mt-0.5 shrink-0 [&_svg]:size-5">{icon}</span><div className="min-w-0"><h2 className="font-display text-xl leading-7">{title}</h2><p className="mt-0.5 font-sans text-[11px] leading-4 text-muted-foreground">{subtitle}</p></div></div>;
}

function Metric({ icon, title, value, suffix, tone, width, progress = false }: { icon: ReactNode; title: string; value: string; suffix?: string; tone: "neutral" | "safe" | "danger" | "violet"; width: string; progress?: boolean }) {
  const toneClass = { neutral: "bg-neutral/60", safe: "bg-safe-muted/60 text-safe-soft", danger: "bg-danger-muted/60 text-danger-icon", violet: "bg-violet-muted/60 text-violet-icon" }[tone];
  return <article className={`relative flex h-[98px] shrink-0 items-center rounded-[25px] border border-frame px-[14px] ${width}`}><span className={`grid size-[50px] shrink-0 place-items-center rounded-full border border-frame/60 ${toneClass} [&_svg]:size-6`}>{icon}</span><div className="min-w-0 flex-1 text-center"><div className="font-sans text-base leading-7">{title}</div><div className="font-numeric text-xl leading-6">{value}<span className="text-base">{suffix}</span></div>{progress && <div className="absolute bottom-[12px] left-[70px] h-1 w-[114px] rounded-full bg-track"><div className="h-full w-[96px] rounded-full bg-progress" /></div>}</div></article>;
}

function Feature({ icon, title, text }: { icon: ReactNode; title: string; text: string }) {
  return <article className="flex h-[82px] min-w-0 items-start gap-2.5 rounded-[25px] border border-frame bg-surface px-3 py-3.5"><span className="shrink-0 [&_svg]:size-5">{icon}</span><div className="min-w-0"><h3 className="font-sans text-[11px] leading-4">{title}</h3><p className="mt-1 font-sans text-[9px] leading-3 text-muted-foreground">{text}</p></div></article>;
}