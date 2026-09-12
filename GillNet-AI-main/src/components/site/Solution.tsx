import diagram from "@/assets/solution-diagram.png";

export function Solution() {
  return (
    <section
      id="solution"
      className="mx-auto max-w-[1440px] scroll-mt-[80px] px-6 pt-12 pb-24 md:px-16 md:pt-20 md:pb-32"
    >
      <div className="grid items-center gap-16 md:grid-cols-2">
        <div>
          <p className="inline-block border-b border-primary pb-1 text-[13px] uppercase tracking-[0.14em]">
            The Solution
          </p>
          <h2 className="mt-5 text-[42px] leading-[1.05] sm:text-[56px] lg:text-[72px]">
            One <span className="italic font-light">Platform,</span>
            <br />
            <span className="italic font-light">Every</span> threat.
          </h2>
          <p className="mt-6 max-w-[440px] text-[14px] font-light italic leading-[1.7] text-primary/90">
            GillNet AI combines the power of Artificial Intelligence with Cybersecurity to detect
            phishing attempts, scam messages, weak passwords and suspicious activity - Before they
            cause any damage.
          </p>
          <div className="mt-10 flex flex-wrap items-center gap-4 text-[16px] italic text-primary">
            {["Detect", "Analyze", "Warn", "Protect"].map((s, i) => (
              <span key={s} className="flex items-center gap-4">
                {i > 0 && <span className="not-italic text-[22px] font-normal leading-none text-primary">·</span>}
                {s}
              </span>
            ))}
          </div>
        </div>

        <div className="flex justify-center">
          <img
            src={diagram}
            alt="GillNet AI security tool diagram connecting passwords, emails, websites and messages"
            className="h-auto w-full max-w-[520px]"
          />
        </div>
      </div>
    </section>
  );
}
