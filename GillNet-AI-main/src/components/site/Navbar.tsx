import { useEffect, useState } from "react";
import { Menu, X, User } from "lucide-react";
import { useAuth } from "@/lib/auth-context";

const links = [
  { label: "Problem", id: "problem" },
  { label: "Solution", id: "solution" },
  { label: "Services", id: "services" },
  { label: "About", id: "team" },
];

function scrollTo(id: string) {
  const el = document.getElementById(id);
  if (!el) return;
  const header = document.getElementById("site-header");
  const offset = (header?.offsetHeight ?? 0) + 12;
  const go = () => {
    const top = el.getBoundingClientRect().top + window.scrollY - offset;
    window.scrollTo({ top, behavior: "smooth" });
  };
  go();
  // re-correct after images/layout settle so we don't land mid-section
  setTimeout(go, 420);
}

export function Navbar() {
  const [open, setOpen] = useState(false);
  const { user, isAuthenticated, logout, openAuthModal } = useAuth();

  useEffect(() => {
    document.body.style.overflow = open ? "hidden" : "";
    return () => {
      document.body.style.overflow = "";
    };
  }, [open]);

  const go = (id: string) => {
    setOpen(false);
    setTimeout(() => scrollTo(id), 10);
  };

  const handleAuthClick = () => {
    setOpen(false);
    if (isAuthenticated) {
      logout();
    } else {
      openAuthModal("login");
    }
  };

  return (
    <header id="site-header" className="sticky top-0 z-50 border-b border-border bg-background">
      <div className="mx-auto flex h-[62px] max-w-[1440px] items-center justify-between gap-4 px-6 md:h-[78px] md:px-10 lg:px-16">
        <a href="#top" className="shrink-0 text-2xl leading-none md:text-[28px] lg:text-[32px]">
          GillNet AI
        </a>

        <nav className="hidden items-center gap-5 md:flex lg:gap-8">
          {links.map((l) => (
            <button
              key={l.id}
              onClick={() => go(l.id)}
              className="text-[17px] leading-none transition-opacity hover:opacity-60 lg:text-[20px] cursor-pointer"
            >
              {l.label}
            </button>
          ))}
        </nav>

        <div className="flex items-center gap-3">
          {isAuthenticated ? (
            <div className="hidden items-center gap-3 md:flex">
              <span className="flex items-center gap-2 rounded-full border border-primary/25 bg-primary/5 px-3 py-1 font-serif text-[15px] lg:text-[17px]">
                {user?.picture ? (
                  <img
                    src={user.picture}
                    alt={user?.name || "User"}
                    className="h-6 w-6 rounded-full object-cover border border-primary/30"
                  />
                ) : (
                  <User size={15} />
                )}
                <span className="max-w-[130px] truncate">{user?.name || user?.email}</span>
              </span>
              <a
                href="/dashboard"
                className="rounded-full bg-primary px-5 py-2 font-serif text-[15px] text-primary-foreground transition-opacity hover:opacity-85 lg:px-6 lg:text-[17px] cursor-pointer"
              >
                Dashboard
              </a>
              <button
                onClick={logout}
                className="rounded-full border border-primary/30 px-4 py-2 font-serif text-[15px] transition-colors hover:bg-primary hover:text-primary-foreground lg:px-5 lg:text-[17px] cursor-pointer"
              >
                Sign Out
              </button>
            </div>
          ) : (
            <button
              onClick={() => openAuthModal("login")}
              className="hidden rounded-full bg-primary px-6 py-2 text-[17px] text-primary-foreground transition-opacity hover:opacity-85 md:block lg:px-7 lg:text-[20px] cursor-pointer"
            >
              Login
            </button>
          )}

          <button
            aria-label={open ? "Close menu" : "Open menu"}
            onClick={() => setOpen((v) => !v)}
            className="grid h-10 w-10 place-items-center rounded-full border border-primary md:hidden cursor-pointer"
          >
            {open ? <X size={20} /> : <Menu size={20} />}
          </button>
        </div>
      </div>

      {open && (
        <div className="border-t border-border bg-background md:hidden">
          <nav className="mx-auto flex max-w-[1440px] flex-col px-6 py-4">
            {links.map((l) => (
              <button
                key={l.id}
                onClick={() => go(l.id)}
                className="border-b border-border py-4 text-left text-[20px]"
              >
                {l.label}
              </button>
            ))}

            {isAuthenticated ? (
              <div className="mt-4 flex flex-col gap-2">
                <div className="flex items-center gap-2 py-2 font-serif text-[17px]">
                  <User size={16} />
                  <span>Logged in as: {user?.name || user?.email}</span>
                </div>
                <a
                  href="/dashboard"
                  className="flex h-[46px] items-center justify-center rounded-full bg-primary font-serif text-[18px] text-primary-foreground cursor-pointer"
                >
                  Open Dashboard →
                </a>
                <button
                  onClick={handleAuthClick}
                  className="h-[46px] rounded-full border border-primary text-[18px] cursor-pointer"
                >
                  Sign Out
                </button>
              </div>
            ) : (
              <button
                onClick={handleAuthClick}
                className="mt-5 h-[46px] rounded-full bg-primary text-[18px] text-primary-foreground"
              >
                Login
              </button>
            )}
          </nav>
        </div>
      )}
    </header>
  );
}
