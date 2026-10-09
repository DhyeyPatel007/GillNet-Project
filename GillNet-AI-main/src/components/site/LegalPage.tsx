import { Link } from "@tanstack/react-router";
import { Navbar } from "@/components/site/Navbar";
import { Footer } from "@/components/site/Footer";
import type { ReactNode } from "react";

export function LegalPage({
  title,
  updated,
  children,
}: {
  title: string;
  updated: string;
  children: ReactNode;
}) {
  return (
    <div className="min-h-screen bg-background text-foreground">
      <Navbar />
      <main className="mx-auto max-w-[800px] px-6 py-16 md:px-10 md:py-24">
        <Link
          to="/"
          className="text-xs font-sans text-muted-foreground hover:text-bright transition-colors"
        >
          ← Back to home
        </Link>
        <h1 className="mt-6 text-3xl md:text-4xl font-semibold text-bright">{title}</h1>
        <p className="mt-2 text-xs font-sans text-muted-foreground">Last updated: {updated}</p>
        <div className="mt-8 space-y-6 text-[15px] leading-[1.75] text-foreground/85 font-sans">
          {children}
        </div>
      </main>
      <Footer />
    </div>
  );
}

export function LegalSection({ heading, children }: { heading: string; children: ReactNode }) {
  return (
    <section>
      <h2 className="text-lg font-semibold text-bright mb-2">{heading}</h2>
      <div className="space-y-2">{children}</div>
    </section>
  );
}
