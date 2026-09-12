import React from "react";
import robot from "@/assets/robot.png";

export function Hero() {
  const scrollToSection = (id: string) => (e: React.MouseEvent<HTMLAnchorElement>) => {
    e.preventDefault();
    const el = document.getElementById(id);
    if (el) {
      const header = document.getElementById("site-header");
      const offset = (header?.offsetHeight ?? 0) + 12;
      const top = el.getBoundingClientRect().top + window.scrollY - offset;
      window.scrollTo({ top, behavior: "smooth" });
    } else {
      window.location.hash = id;
    }
  };

  return (
    <section
      id="top"
      className="mx-auto flex max-w-[1440px] flex-col justify-center px-6 md:min-h-[calc(100svh-78px)] md:px-16"
    >
      <div className="grid items-center gap-2 py-8 md:grid-cols-[minmax(0,1fr)_minmax(0,0.85fr)] md:gap-8 md:py-4">
        <div className="min-w-0 md:w-fit">
          <h1 className="text-[46px] leading-[1.02] tracking-tight sm:text-[64px] lg:text-[84px] xl:text-[100px]">
            <span className="block whitespace-nowrap">
              <span className="font-normal">Stay </span>
              <span className="font-light italic">Secure.</span>
            </span>
            <span className="block whitespace-nowrap pl-[0.5em]">
              <span className="font-normal">Stay </span>
              <span className="font-normal">Ahead.</span>
            </span>
          </h1>

          <div className="pl-[23px] sm:pl-[32px] lg:pl-[42px] xl:pl-[50px]">
          <p className="mx-auto mt-6 w-full max-w-[440px] text-center text-[14px] font-light italic leading-[1.6] text-primary/90 md:mt-7">
            Detect phishing websites, uncover scam messages, strengthen your passwords, and protect
            your digital life with AI-Powered Cybersecurity tool.
          </p>

          <div className="mt-6 flex flex-wrap justify-center gap-3 md:gap-4">
            <a
              href="#services"
              onClick={scrollToSection("services")}
              className="flex items-center justify-center h-[42px] w-[150px] rounded-full border border-primary text-[15px] transition-colors hover:bg-primary hover:text-primary-foreground md:h-[46px] md:w-[168px] md:text-[17px] cursor-pointer"
            >
              Start Protecting
            </a>
            <a
              href="#solution"
              onClick={scrollToSection("solution")}
              className="flex items-center justify-center h-[42px] w-[150px] rounded-full bg-primary text-[15px] text-primary-foreground transition-opacity hover:opacity-85 md:h-[46px] md:w-[168px] md:text-[17px] cursor-pointer"
            >
              Watch Demo
            </a>
          </div>
          </div>
        </div>



        <div className="flex min-w-0 items-center justify-center md:justify-end">
          <img
            src={robot}
            alt="Black futuristic AI robot"
            className="h-auto w-[260px] max-w-full object-contain sm:w-[320px] md:max-h-[68svh] md:w-full"
          />
        </div>
      </div>
    </section>
  );
}
