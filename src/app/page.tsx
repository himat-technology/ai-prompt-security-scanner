import { PromptScanner } from "@/components/scanner/PromptScanner";
import { ToolInfoSections } from "@/components/ToolInfoSections";
import { HIMAT } from "@/lib/himat";

export default function HomePage() {
  return (
    <div className="mx-auto max-w-6xl px-4 py-10 sm:px-6 sm:py-14">
      <header className="relative mx-auto max-w-3xl text-center">
        <div
          className="pointer-events-none absolute left-1/2 top-0 h-40 w-40 -translate-x-1/2 rounded-full bg-cyan-400/30 blur-3xl animate-float-soft"
          aria-hidden="true"
        />
        <div
          className="pointer-events-none absolute -right-4 top-10 h-28 w-28 rounded-full bg-rose-400/25 blur-3xl animate-float-soft-delayed"
          aria-hidden="true"
        />

        <p className="relative inline-flex items-center gap-2 rounded-full border border-cyan-300/30 bg-cyan-400/10 px-3 py-1 text-[11px] font-bold uppercase tracking-[0.18em] text-cyan-200">
          <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 shadow-[0_0_10px_#34d399]" />
          100% Browser-Local Security Scan & Privacy First
        </p>

        <h1 className="relative mt-5 text-3xl font-bold tracking-tight text-white sm:text-4xl md:text-5xl">
          <span className="text-gradient-hero">
            AI Prompt Security & Injection Scanner
          </span>
        </h1>

        <p className="relative mt-4 text-base leading-relaxed text-slate-300 sm:text-lg">
          Scan AI prompts, system instructions, agent inputs, and MCP context
          blocks for security vulnerabilities.
        </p>

        <p className="relative mt-3 text-sm font-semibold text-emerald-300">
          Your prompt data never leaves your browser.
        </p>

        <div className="relative mt-6 flex flex-wrap items-center justify-center gap-2">
          <a
            href={HIMAT.demo}
            target="_blank"
            rel="noopener noreferrer"
            className="rounded-full bg-gradient-to-r from-cyan-400 via-teal-400 to-emerald-400 px-4 py-2 text-sm font-bold text-slate-950 shadow-lg shadow-cyan-500/30 transition hover:brightness-110 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-cyan-300"
          >
            Live Demo on himat.tech
          </a>
          <a
            href={`mailto:${HIMAT.email}`}
            className="rounded-full border border-white/20 bg-white/10 px-4 py-2 text-sm font-semibold text-white transition hover:bg-white/20 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-cyan-300"
          >
            {HIMAT.email}
          </a>
          <a
            href={`tel:${HIMAT.phoneTel}`}
            className="rounded-full border border-amber-300/30 bg-amber-400/10 px-4 py-2 text-sm font-semibold text-amber-100 transition hover:bg-amber-400/20 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-amber-300"
          >
            {HIMAT.phoneDisplay}
          </a>
        </div>
      </header>

      <div className="mt-10">
        <PromptScanner />
      </div>

      <ToolInfoSections />
    </div>
  );
}
