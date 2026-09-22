import Link from "next/link";
import { HIMAT } from "@/lib/himat";

const socialLinks = [
  { label: "Facebook", href: HIMAT.social.facebook, color: "hover:text-sky-300" },
  { label: "LinkedIn", href: HIMAT.social.linkedin, color: "hover:text-cyan-300" },
  { label: "Instagram", href: HIMAT.social.instagram, color: "hover:text-rose-300" },
  { label: "GitHub", href: HIMAT.social.github, color: "hover:text-emerald-300" },
] as const;

export function SiteHeader() {
  return (
    <header className="sticky top-0 z-40 border-b border-white/20 bg-slate-950/80 backdrop-blur-xl">
      <div className="mx-auto flex max-w-6xl items-center justify-between gap-4 px-4 py-3.5 sm:px-6">
        <Link
          href="/"
          className="group flex items-center gap-2.5 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-cyan-400"
        >
          <span
            className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-cyan-400 via-teal-500 to-emerald-500 text-sm font-bold tracking-tight text-white shadow-lg shadow-teal-500/40"
            aria-hidden="true"
          >
            H
          </span>
          <span>
            <span className="block text-sm font-bold tracking-tight text-white group-hover:text-cyan-200">
              {HIMAT.name}
            </span>
            <span className="block text-[11px] font-medium uppercase tracking-wider text-teal-200/80">
              Free Security Tools
            </span>
          </span>
        </Link>

        <div className="flex items-center gap-2 sm:gap-3">
          <a
            href={HIMAT.demo}
            target="_blank"
            rel="noopener noreferrer"
            className="hidden rounded-full bg-gradient-to-r from-cyan-400 to-teal-400 px-3.5 py-1.5 text-xs font-bold text-slate-950 shadow-md shadow-cyan-500/30 transition hover:brightness-110 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-cyan-300 sm:inline-flex"
          >
            Live Demo
          </a>
          <a
            href={HIMAT.social.github}
            target="_blank"
            rel="noopener noreferrer"
            className="rounded-full border border-white/20 bg-white/10 px-3 py-1.5 text-xs font-semibold text-white transition hover:bg-white/20 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-cyan-300"
          >
            Open Source
          </a>
        </div>
      </div>
    </header>
  );
}

export function SiteFooter() {
  return (
    <footer className="relative mt-20 overflow-hidden border-t border-white/10 bg-slate-950 text-slate-200">
      <div
        className="pointer-events-none absolute inset-0 opacity-40"
        aria-hidden="true"
      >
        <div className="absolute -left-20 bottom-0 h-56 w-56 rounded-full bg-cyan-500/30 blur-3xl" />
        <div className="absolute -right-10 top-0 h-48 w-48 rounded-full bg-rose-500/20 blur-3xl" />
        <div className="absolute left-1/2 top-1/2 h-40 w-40 -translate-x-1/2 rounded-full bg-amber-400/20 blur-3xl" />
      </div>

      <div className="relative mx-auto max-w-6xl px-4 py-12 sm:px-6">
        <div className="grid gap-10 md:grid-cols-3">
          <div>
            <p className="text-lg font-bold text-white">{HIMAT.name}</p>
            <p className="mt-2 text-sm leading-relaxed text-slate-400">
              AI-first software development · Free browser-local security tools.
            </p>
            <a
              href={HIMAT.demo}
              target="_blank"
              rel="noopener noreferrer"
              className="mt-4 inline-flex rounded-full bg-gradient-to-r from-cyan-400 via-teal-400 to-emerald-400 px-4 py-2 text-xs font-bold text-slate-950 shadow-lg shadow-teal-500/30 transition hover:brightness-110"
            >
              Open live demo
            </a>
          </div>

          <div>
            <p className="text-xs font-bold uppercase tracking-[0.16em] text-cyan-300">
              Contact
            </p>
            <ul className="mt-3 space-y-2 text-sm">
              <li>
                <a
                  href={HIMAT.website}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-slate-300 transition hover:text-cyan-300"
                >
                  {HIMAT.website.replace("https://", "")}
                </a>
              </li>
              <li>
                <a
                  href={`mailto:${HIMAT.email}`}
                  className="text-slate-300 transition hover:text-amber-300"
                >
                  {HIMAT.email}
                </a>
              </li>
              <li>
                <a
                  href={`tel:${HIMAT.phoneTel}`}
                  className="text-slate-300 transition hover:text-emerald-300"
                >
                  {HIMAT.phoneDisplay}
                </a>
              </li>
            </ul>
          </div>

          <div>
            <p className="text-xs font-bold uppercase tracking-[0.16em] text-rose-300">
              Social
            </p>
            <ul className="mt-3 flex flex-wrap gap-2">
              {socialLinks.map((link) => (
                <li key={link.label}>
                  <a
                    href={link.href}
                    target="_blank"
                    rel="noopener noreferrer"
                    className={`inline-flex rounded-full border border-white/15 bg-white/5 px-3 py-1.5 text-xs font-semibold text-slate-200 transition ${link.color} hover:border-white/30 hover:bg-white/10`}
                  >
                    {link.label}
                  </a>
                </li>
              ))}
            </ul>
          </div>
        </div>

        <div className="mt-10 flex flex-col gap-2 border-t border-white/10 pt-6 sm:flex-row sm:items-center sm:justify-between">
          <p className="text-sm text-slate-400">
            © {new Date().getFullYear()} {HIMAT.name}. MIT Licensed.
          </p>
          <p className="text-xs text-slate-500">
            Pattern-based scanner — not a guarantee of complete security.
          </p>
        </div>
      </div>
    </footer>
  );
}
