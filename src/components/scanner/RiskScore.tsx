"use client";

import type { ScanResult } from "@/lib/security-scanner";
import { SEVERITY_LABELS } from "@/lib/security-scanner";

interface RiskScoreProps {
  result: ScanResult | null;
  hasScanned: boolean;
  isEmpty: boolean;
}

function severityStyles(severity: ScanResult["severity"]) {
  switch (severity) {
    case "critical":
      return {
        badge: "bg-gradient-to-r from-rose-600 to-red-600 text-white shadow-md shadow-rose-500/30",
        ring: "stroke-rose-500",
        track: "stroke-rose-100",
        card: "border-rose-300/50",
      };
    case "high":
      return {
        badge: "bg-gradient-to-r from-orange-500 to-amber-500 text-white shadow-md shadow-orange-500/30",
        ring: "stroke-orange-500",
        track: "stroke-orange-100",
        card: "border-orange-300/50",
      };
    case "medium":
      return {
        badge: "bg-gradient-to-r from-amber-400 to-yellow-400 text-slate-900 shadow-md shadow-amber-400/30",
        ring: "stroke-amber-500",
        track: "stroke-amber-100",
        card: "border-amber-300/50",
      };
    default:
      return {
        badge: "bg-gradient-to-r from-emerald-500 to-teal-500 text-white shadow-md shadow-emerald-500/30",
        ring: "stroke-emerald-500",
        track: "stroke-emerald-100",
        card: "border-emerald-300/50",
      };
  }
}

export function RiskScore({ result, hasScanned, isEmpty }: RiskScoreProps) {
  if (isEmpty && !hasScanned) {
    return (
      <section
        className="rounded-2xl border border-dashed border-cyan-300/40 bg-white/90 p-6 shadow-lg"
        aria-labelledby="risk-heading"
      >
        <h2 id="risk-heading" className="text-lg font-semibold text-slate-900">
          Security Risk Score
        </h2>
        <p className="mt-2 text-sm text-slate-600">
          Enter a prompt or context block to scan.
        </p>
      </section>
    );
  }

  if (!result) {
    return (
      <section
        className="rounded-2xl border border-cyan-200 bg-gradient-to-br from-white to-cyan-50 p-6 shadow-xl shadow-cyan-950/10"
        aria-labelledby="risk-heading"
      >
        <h2 id="risk-heading" className="text-lg font-semibold text-slate-900">
          Security Risk Score
        </h2>
        <p className="mt-2 text-sm text-slate-600">
          Click Scan Prompt to analyze your input locally.
        </p>
      </section>
    );
  }

  const styles = severityStyles(result.severity);
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const progress = (result.riskScore / 100) * circumference;
  const threatLabel =
    result.statistics.findingCount === 1
      ? "1 Threat Vector Found"
      : `${result.statistics.findingCount} Threat Vectors Found`;

  return (
    <section
      className={`rounded-2xl border bg-gradient-to-br from-white via-white to-slate-50 p-6 shadow-xl ${styles.card}`}
      aria-labelledby="risk-heading"
      aria-live="polite"
    >
      <h2 id="risk-heading" className="text-lg font-semibold text-slate-900">
        Security Risk Score
      </h2>

      <div className="mt-4 flex flex-col items-center gap-4 sm:flex-row sm:items-center">
        <div className="relative h-36 w-36 shrink-0" aria-hidden="true">
          <svg viewBox="0 0 128 128" className="h-full w-full -rotate-90">
            <circle
              cx="64"
              cy="64"
              r={radius}
              fill="none"
              strokeWidth="10"
              className={styles.track}
            />
            <circle
              cx="64"
              cy="64"
              r={radius}
              fill="none"
              strokeWidth="10"
              strokeLinecap="round"
              strokeDasharray={circumference}
              strokeDashoffset={circumference - progress}
              className={`${styles.ring} transition-[stroke-dashoffset] duration-500`}
            />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center rotate-0">
            <span className="text-3xl font-bold tabular-nums text-slate-900">
              {result.riskScore}
            </span>
            <span className="text-xs font-medium text-slate-500">/ 100</span>
          </div>
        </div>

        <div className="min-w-0 flex-1 space-y-2 text-center sm:text-left">
          <p>
            <span
              className={`inline-flex items-center rounded-full px-3 py-1 text-sm font-bold ${styles.badge}`}
            >
              {SEVERITY_LABELS[result.severity]}
            </span>
          </p>
          <p className="text-base font-semibold text-slate-900">{threatLabel}</p>
          <p className="text-sm text-slate-600">
            {result.statistics.findingCount === 0
              ? "No security threats detected."
              : "Security threats detected. Review detailed match findings and use the hardened prompt output below."}
          </p>
        </div>
      </div>

      <div className="mt-5 rounded-xl border border-cyan-200 bg-gradient-to-r from-cyan-50 via-teal-50 to-emerald-50 px-4 py-3">
        <p className="text-sm font-semibold text-teal-900">
          100% Client-Side Local Scan Guarantee
        </p>
        <p className="mt-1 text-xs leading-relaxed text-teal-800">
          Scanning operates entirely inside your web browser. Neither your
          prompts, system context, nor detected API keys are sent over the
          network.
        </p>
      </div>
    </section>
  );
}
