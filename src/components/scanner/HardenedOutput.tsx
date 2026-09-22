"use client";

import { useState } from "react";
import { copyToClipboard } from "@/lib/browser";

interface HardenedOutputProps {
  sanitizedPrompt: string;
  hasScanned: boolean;
}

export function HardenedOutput({
  sanitizedPrompt,
  hasScanned,
}: HardenedOutputProps) {
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState(false);

  if (!hasScanned) return null;

  async function handleCopy() {
    if (!sanitizedPrompt) return;
    const ok = await copyToClipboard(sanitizedPrompt);
    if (!ok) {
      setError(true);
      setCopied(false);
      return;
    }
    setError(false);
    setCopied(true);
    window.setTimeout(() => setCopied(false), 2000);
  }

  return (
    <section
      className="rounded-2xl border border-emerald-200/60 bg-gradient-to-br from-white to-emerald-50/50 p-6 shadow-xl shadow-emerald-950/10"
      aria-labelledby="hardened-heading"
    >
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h2
            id="hardened-heading"
            className="text-lg font-semibold text-slate-900"
          >
            Automated Hardened & Sanitized Output Prompt
          </h2>
          <p className="mt-1 text-sm text-slate-600">
            Injections stripped, sensitive keys redacted, and untrusted input
            wrapped in defensive XML tags (
            <code className="rounded bg-emerald-100 px-1 text-xs text-emerald-900">
              &lt;user_untrusted_input&gt;
            </code>
            ).
          </p>
        </div>
        <button
          type="button"
          onClick={handleCopy}
          disabled={!sanitizedPrompt}
          className="inline-flex items-center justify-center rounded-full bg-gradient-to-r from-emerald-500 to-teal-500 px-4 py-2 text-sm font-bold text-white shadow-lg shadow-emerald-500/30 transition hover:brightness-110 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-emerald-500 disabled:cursor-not-allowed disabled:opacity-50"
        >
          {copied ? "Copied" : "Copy Hardened Prompt"}
        </button>
      </div>

      <pre className="mt-4 max-h-80 overflow-auto rounded-xl border border-emerald-900/40 bg-slate-950 p-4 font-mono text-sm leading-relaxed text-emerald-100">
        {sanitizedPrompt || "(empty)"}
      </pre>

      {error && (
        <p className="mt-3 text-sm font-medium text-rose-700" role="alert">
          Unable to copy automatically. Please copy the text manually.
        </p>
      )}
    </section>
  );
}
