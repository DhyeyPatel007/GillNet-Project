import team from "@/assets/team-panel.png";

export function Team() {
  return (
    <section id="team" className="mx-auto max-w-[1440px] px-6 py-20 md:px-16 md:py-28">
      <p className="inline-block border-b border-primary pb-1 text-[13px] uppercase tracking-[0.14em]">
        The Team
      </p>
      <h2 className="mt-5 text-[36px] leading-[1.08] sm:text-[48px] lg:text-[60px]">
        The <span className="italic font-light">Team</span> Behind
        <br />
        GillNet AI.
      </h2>

      <div className="mt-12">
        <img
          src={team}
          alt="The five GillNet AI team members with their roles"
          className="mx-auto w-full max-w-[1100px]"
        />
      </div>
    </section>
  );
}
