import spiral from "@/assets/element-cropped.png";
import users from "@/assets/libre-gui-users_logo.png";
import lock from "@/assets/Vector.png";
import globe from "@/assets/Vector_1.png";

const threats = [
  { label: "Scammers", icon: users },
  { label: "Weak Passcode", icon: lock },
  { label: "Phishing Websites", icon: globe },
];

export function Problem() {
  return (
    <section id="problem" className="mx-auto max-w-[1440px] px-6 py-20 md:px-16 md:py-28">
      <div className="grid gap-12 md:grid-cols-[0.8fr_1.2fr] md:items-start">
        <div className="order-2 flex items-start justify-center md:order-1 md:justify-start">
          <img
            src={spiral}
            alt="Black spiral object"
            className="mt-6 w-[300px] max-w-full sm:w-[380px] lg:w-[440px] xl:w-[500px]"
          />
        </div>

        <div className="order-1 md:order-2 md:text-right">
          <p className="inline-block border-b border-primary pb-1 text-[13px] uppercase tracking-[0.14em]">
            The Problem
          </p>
          <h2 className="mt-6 leading-[1.05]" style={{ fontSize: "clamp(22px, 4.4vw, 85px)" }}>
            <span className="block whitespace-nowrap">
              The <span className="font-normal">Digital</span>{" "}
              <span className="italic font-light">World</span>
            </span>
            <span className="block whitespace-nowrap">
              Rewards <span className="italic font-light">Convenience.</span>
            </span>
            <span className="block whitespace-nowrap">
              <span className="italic font-light">Attackers</span> Depend On It.
            </span>
          </h2>

          <p className="mt-6 text-[14px] font-light italic leading-[1.6] text-primary/90 md:ml-auto md:max-w-[520px]">
            Every click, password, and message creates an opportunity for cybercriminals. Most
            attacks don't exploit software—they exploit human trust.
          </p>

          <div className="mt-8 flex flex-col items-end gap-3">
            {threats.map((t) => (
              <div
                key={t.label}
                className="flex w-auto items-center justify-between gap-5 rounded-[25px] border-[1.5px] border-primary py-1.5 pl-6 pr-1.5"
              >
                <span className="text-[20px] leading-none">{t.label}</span>
                <span className="flex h-[34px] w-[34px] shrink-0 items-center justify-center rounded-full border-[1.5px] border-primary">
                  <img src={t.icon} alt="" className="h-4 w-4 object-contain" />
                </span>
              </div>
            ))}
          </div>



        </div>
      </div>
    </section>
  );
}
