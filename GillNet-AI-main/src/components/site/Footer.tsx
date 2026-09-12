export function Footer() {
  return (
    <footer className="bg-primary text-primary-foreground">
      <div className="mx-auto grid max-w-[1440px] gap-10 px-6 py-16 md:grid-cols-2 md:px-16">
        <div>
          <p className="text-[44px] leading-none md:text-[56px]">GillNet AI.</p>
          <p className="mt-4 inline-block border-b border-primary-foreground/50 pb-1 text-[13px] uppercase tracking-[0.14em]">
            AI - Powered Cybersecurity
          </p>
          <p className="mt-10 text-[14px] font-light italic leading-[1.6] text-primary-foreground/90">
            Project Exhibition - I
            <br />
            VIT Bhopal University
          </p>
        </div>

        <div className="md:text-right">
          <p className="text-[14px] font-light italic leading-[1.7] text-primary-foreground/90 md:ml-auto md:max-w-[520px]">
            GillNet AI is an academic cybersecurity project that explores the integration of
            Artificial Intelligence with modern security practices. Designed to detect phishing
            attempts, strengthen password security, and promote safer digital experiences through
            intelligent automation.
          </p>
          <p className="mt-16 text-[14px]">© 2026 GillNet AI</p>
        </div>
      </div>
    </footer>
  );
}
