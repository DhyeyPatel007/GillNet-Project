import sphere from "@/assets/Union.png";

const services = [
  {
    n: "01",
    title: "Email Protection",
    desc: "Detect phishing emails, malicious attachments, and scam emails before they reach you.",
    points: ["Attachment Scanning", "URL Scanning", "Phishing Detection"],
  },
  {
    n: "02",
    title: "Password Security",
    desc: "Recognise weak passwords, insecure combinations, and protect your accounts before they are compromised.",
    points: ["Weak Password Detection", "Password Strength Analysis", "Breach Monitoring"],
  },
  {
    n: "03",
    title: "Website Safety",
    desc: "Identify malicious websites, phishing pages and unsafe links before you interact with them.",
    points: ["Phishing Website Detection", "Malware Scanning", "Safe Browsing Analysis"],
  },
  {
    n: "04",
    title: "Message Protection",
    desc: "Detect scam messages, fraudulent links, and suspicious conversations across your messaging platforms.",
    points: ["Scam Message Detection", "Link Verification", "Behavioural Analysis"],
  },
];

export function Services() {
  return (
    <section id="services" className="border-y border-border scroll-mt-[80px]">
      <div className="mx-auto max-w-[1440px] px-6 py-20 md:px-16 md:py-28">
        <div className="grid items-center gap-12 md:grid-cols-[0.8fr_1.2fr]">
          <div className="order-2 flex justify-center md:order-1">
            <img src={sphere} alt="Wireframe geometric sphere" className="w-[300px] max-w-full lg:w-[400px]" />
          </div>

          <div className="order-1 md:order-2 md:text-right">
            <p className="inline-block border-b border-primary pb-1 text-[13px] uppercase tracking-[0.14em]">
              Our Services
            </p>
            <h2 className="mt-6 leading-[1.05]" style={{ fontSize: "clamp(22px, 4.4vw, 85px)" }}>
              <span className="block whitespace-nowrap">Comprehensive</span>
              <span className="block whitespace-nowrap">
                <span className="italic font-light">Protection.</span> Powered
              </span>
              <span className="block whitespace-nowrap">
                By <span className="italic font-light">Intelligence.</span>
              </span>
            </h2>
            <p className="mt-6 text-[14px] font-light italic leading-[1.6] text-primary/90 md:ml-auto md:max-w-[520px]">
              GillNet AI provides various AI - Powered Cybersecurity Tools that detect, analyze, and
              neutralize digital threats in Real Life.
            </p>
            <button className="mt-8 rounded-full bg-primary px-8 py-3 text-[18px] text-primary-foreground transition-opacity hover:opacity-85">
              Explore Services
            </button>
          </div>
        </div>

        <div className="mt-16 grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
          {services.map((s) => (
            <article key={s.n} className="rounded-lg border border-primary p-6">
              <p className="text-[14px] font-light italic text-primary/90">Service</p>
              <p className="mt-3 text-[32px] leading-none">{s.n}</p>
              <h3 className="mt-6 border-b border-primary pb-3 text-[17px]">{s.title}</h3>
              <p className="mt-4 text-[14px] font-light italic leading-[1.6] text-primary/90">{s.desc}</p>
              <ul className="mt-5 space-y-1 text-[14px] font-light italic text-primary/90">
                {s.points.map((p) => (
                  <li key={p}>·{p}</li>
                ))}
              </ul>
            </article>
          ))}
        </div>
      </div>
    </section>
  );
}
