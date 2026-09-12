const items = [
  "Phishing Protection",
  "Scam Detection",
  "Password Security",
  "AI Powered Cyber Assistant",
];

export function Marquee() {
  const row = (
    <div className="flex shrink-0 items-center gap-8 pr-8">
      {items.map((t) => (
        <span key={t} className="flex items-center gap-8 whitespace-nowrap">
          <span className="text-[20px] italic md:text-[28px]">{t}</span>
          <span className="text-[18px]">·</span>
        </span>
      ))}
    </div>
  );

  return (
    <div className="w-full overflow-hidden bg-primary py-4 text-primary-foreground">
      <div className="flex w-max animate-[marquee_28s_linear_infinite]">
        {row}
        {row}
      </div>
    </div>
  );
}
