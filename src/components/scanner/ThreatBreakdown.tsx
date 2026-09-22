"use client";

import { useState } from "react";
import type { ThreatFinding } from "@/lib/security-scanner";
import { CATEGORY_LABELS, SEVERITY_LABELS } from "@/lib/security-scanner";
import { copyToClipboard } from "@/lib/browser";

interface ThreatBreakdownProps {
  findings: ThreatFinding[];
  hasScanned: boolean;
  onExportJson: () => void;
  onExportMarkdown: () => void;
}

function severityBadgeClass(severity: ThreatFinding["severity"]): string {
  switch (severity) {
    case "critical":
      return "bg-red-100 text-red-800 ring-red-300";
    case "high":
      return "bg-orange-100 text-orange-800 ring-orange-300";
    case "medium":
      return "bg-amber-100 text-amber-900 ring-amber-300";
    default:
      return "bg-sky-100 text-sky-800 ring-sky-300";
  }
}

export function ThreatBreakdown({
  findings,
  hasScanned,
  onExportJson,
  onExportMarkdown,
}: ThreatBreakdownProps) {
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [copyError, setCopyError] = useState(false);

  async function handleCopyFinding(finding: ThreatFinding) {
    const text = [
      finding.title,
      `Severity: ${finding.severity}`,
      `Category: ${CATEGORY_LABELS[finding.category]}`,
      `Matched: ${finding.displaySnippet ?? finding.matchedSnippet}`,
      finding.description,
      `Recommendation: ${finding.recommendation}`,
    ].join("\n");

    const ok = await copyToClipboard(text);
    if (!ok) {
      setCopyError(true);
      return;
    }
    setCopyError(false);
    setCopiedId(finding.id);
    window.setTimeout(() => setCopiedId(null), 2000);
  }

  if (!hasScanned) {
    return null;
  }

  return (
    <section
      className="rounded-2xl border border-orange-200/60 bg-gradient-to-br from-white to-orange-50/40 p-6 shadow-xl shadow-orange-950/10"
      aria-labelledby="breakdown-heading"
      aria-live="polite"
    >
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div>
          <h2
            id="breakdown-heading"
            className="text-lg font-semibold text-slate-900"
          >
            Detected Threat Breakdown ({findings.length})
          </h2>
          <p className="mt-1 text-sm text-slate-600">
            Each finding includes severity, category, matched snippet, and a
            remediation recommendation.
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <button
            type="button"
            onClick={onExportJson}
            className="rounded-full border border-sky-300 bg-sky-50 px-3 py-1.5 text-sm font-semibold text-sky-900 transition hover:bg-sky-100 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-sky-500"
          >
            Export Audit JSON
          </button>
          <button
            type="button"
            onClick={onExportMarkdown}
            className="rounded-full border border-violet-300 bg-violet-50 px-3 py-1.5 text-sm font-semibold text-violet-900 transition hover:bg-violet-100 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-violet-500"
          >
            Export Markdown Report
          </button>
        </div>
      </div>

      {findings.length === 0 ? (
        <p className="mt-4 rounded-lg border border-emerald-200 bg-emerald-50 px-4 py-3 text-sm text-emerald-900">
          No security threats detected.
        </p>
      ) : (
        <ul className="mt-4 space-y-3">
          {findings.map((finding) => (
            <li
              key={finding.id}
              className="rounded-lg border border-slate-200 bg-slate-50/60 p-4"
            >
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div>
                  <h3 className="text-base font-semibold text-slate-900">
                    {finding.title}
                    <span className="ml-2 text-sm font-normal text-slate-500">
                      ({CATEGORY_LABELS[finding.category]})
                    </span>
                  </h3>
                  <div className="mt-2 flex flex-wrap gap-2">
                    <span
                      className={`inline-flex items-center rounded-md px-2 py-0.5 text-xs font-semibold ring-1 ring-inset ${severityBadgeClass(finding.severity)}`}
                    >
                      {SEVERITY_LABELS[finding.severity].replace(" Risk", "")} ·{" "}
                      {finding.severity}
                    </span>
                    <span className="inline-flex items-center rounded-md bg-slate-200/80 px-2 py-0.5 text-xs font-medium text-slate-700">
                      {CATEGORY_LABELS[finding.category]}
                    </span>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => handleCopyFinding(finding)}
                  className="rounded-md border border-slate-300 bg-white px-2.5 py-1 text-xs font-medium text-slate-700 hover:bg-slate-50 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-teal-600"
                >
                  {copiedId === finding.id ? "Copied" : "Copy Finding"}
                </button>
              </div>

              <p className="mt-3 text-sm text-slate-700">{finding.description}</p>

              <div className="mt-3">
                <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                  Matched Snippet
                </p>
                <p className="mt-1 rounded-md border border-slate-200 bg-white px-3 py-2 font-mono text-sm text-slate-800">
                  “{finding.displaySnippet ?? finding.matchedSnippet}”
                </p>
              </div>

              <div className="mt-3">
                <p className="text-xs font-semibold uppercase tracking-wide text-slate-500">
                  Recommendation
                </p>
                <p className="mt-1 text-sm text-slate-700">
                  {finding.recommendation}
                </p>
              </div>
            </li>
          ))}
        </ul>
      )}

      {copyError && (
        <p className="mt-3 text-sm text-red-700" role="alert">
          Unable to copy automatically. Please copy the text manually.
        </p>
      )}
    </section>
  );
}
