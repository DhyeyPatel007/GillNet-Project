import { createFileRoute } from "@tanstack/react-router";
import { Navbar } from "@/components/site/Navbar";
import { Hero } from "@/components/site/Hero";
import { Quote } from "@/components/site/Quote";
import { Marquee } from "@/components/site/Marquee";
import { Problem } from "@/components/site/Problem";
import { Solution } from "@/components/site/Solution";
import { Services } from "@/components/site/Services";
import { Team } from "@/components/site/Team";
import { CTA } from "@/components/site/CTA";
import { Footer } from "@/components/site/Footer";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "GillNet AI — AI-Powered Cybersecurity" },
      {
        name: "description",
        content:
          "GillNet AI detects phishing websites, uncovers scam messages, and strengthens passwords with AI-powered cybersecurity.",
      },
      { property: "og:title", content: "GillNet AI — AI-Powered Cybersecurity" },
      {
        property: "og:description",
        content:
          "Detect phishing websites, uncover scam messages, and protect your digital life with AI-powered cybersecurity.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: Index,
});

function Index() {
  return (
    <div className="min-h-screen bg-background text-foreground">
      <Navbar />
      <main>
        <Hero />
        <Quote />
        <Marquee />
        <Problem />
        <Solution />
        <Services />
        <Team />
        <CTA />
      </main>
      <Footer />
    </div>
  );
}
