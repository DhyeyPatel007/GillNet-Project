import { useAuth } from "@/lib/auth-context";

export function CTA() {
  const { isAuthenticated, user, openAuthModal } = useAuth();

  const handleStartProtecting = () => {
    if (isAuthenticated) {
      window.location.href = "/dashboard";
    } else {
      openAuthModal("register");
    }
  };

  return (
    <section id="cta" className="border-t border-border">
      <div className="mx-auto max-w-[1440px] px-6 py-24 text-center md:px-16 md:py-32">
        <h2 className="mx-auto max-w-[720px] text-[42px] leading-[1.05] sm:text-[56px] lg:text-[68px]">
          Ready To <span className="italic font-light">Stay</span>
          <br />
          Secure?
        </h2>
        <p className="mx-auto mt-8 max-w-[620px] text-[14px] font-light italic leading-[1.6] text-primary/90">
          Protect your inbox, passwords, websites, and digital identity with intelligent AI-powered
          cybersecurity. Stay ahead of evolving threats with continuous monitoring, instant
          analysis, and proactive protection designed for the modern digital world.
        </p>
        <button
          onClick={handleStartProtecting}
          className="mt-10 h-[50px] min-w-[195px] px-6 rounded-full bg-primary text-[20px] text-primary-foreground transition-opacity hover:opacity-85 cursor-pointer"
        >
          {isAuthenticated ? "Go to Dashboard →" : "Start Protecting"}
        </button>

        <div className="mx-auto mt-14 flex max-w-[720px] items-center gap-6">
          <span className="h-px flex-1 bg-primary/40" />
          <p className="max-w-[380px] text-[14px] font-light italic leading-[1.5] text-primary/90">
            "Security is not a product, but a process." - Bruce Schneier
          </p>
          <span className="h-px flex-1 bg-primary/40" />
        </div>
      </div>
    </section>
  );
}
