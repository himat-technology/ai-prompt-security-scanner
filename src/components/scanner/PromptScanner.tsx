"use client";

import {
  useCallback,
  useId,
  useMemo,
  useState,
  useTransition,
} from "react";
import {
  ATTACK_PRESETS,
  DEFAULT_SAMPLE,
  SCANNER_VERSION,
  buildAuditReport,
  buildMarkdownReport,
  scanPrompt,
  type AttackPreset,
  type ScanResult,
} from "@/lib/security-scanner";
import { downloadTextFile } from "@/lib/browser";
import { HighlightedText } from "./HighlightedText";
import { PresetAttacks } from "./PresetAttacks";
import { RiskScore } from "./RiskScore";
import { ThreatBreakdown } from "./ThreatBreakdown";
import { HardenedOutput } from "./HardenedOutput";

export function PromptScanner() {
  const inputId = useId();
  const [input, setInput] = useState(DEFAULT_SAMPLE);
  const [activePresetId, setActivePresetId] = useState<string | null>(
    ATTACK_PRESETS[0]?.id ?? null
  );
  const [result, setResult] = useState<ScanResult | null>(null);
  const [hasScanned, setHasScanned] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isPending, startTransition] = useTransition();

  const characterCount = input.length;
  const isEmpty = input.trim().length === 0;

  const runScan = useCallback(() => {
    if (isEmpty) {
      setResult(null);
      setHasScanned(false);
      setError(null);
      return;
    }

    startTransition(() => {
      try {
        const next = scanPrompt(input);
        setResult(next);
        setHasScanned(true);
        setError(null);
      } catch {
        setError("Unable to complete the scan. Please try again.");
        setHasScanned(false);
        setResult(null);
      }
    });
  }, [input, isEmpty]);

  const handlePreset = useCallback((preset: AttackPreset) => {
    setInput(preset.sample);
    setActivePresetId(preset.id);
    setHasScanned(false);
    setResult(null);
    setError(null);
  }, []);

  const handleClear = useCallback(() => {
    setInput("");
    setActivePresetId(null);
    setHasScanned(false);
    setResult(null);
    setError(null);
  }, []);

  const handleLoadSample = useCallback(() => {
    handlePreset(ATTACK_PRESETS[0]);
  }, [handlePreset]);

  const exportJson = useCallback(() => {
    if (!result) return;
    const report = buildAuditReport(result);
    downloadTextFile(
      `prompt-security-audit-${SCANNER_VERSION}.json`,
      JSON.stringify(report, null, 2),
      "application/json"
    );
  }, [result]);

  const exportMarkdown = useCallback(() => {
    if (!result) return;
    const markdown = buildMarkdownReport(result);
    downloadTextFile(
      `prompt-security-audit-${SCANNER_VERSION}.md`,
      markdown,
      "text/markdown"
    );
  }, [result]);

  const findings = useMemo(() => result?.findings ?? [], [result]);
  const highlightFindings = findings;

  return (
    <div className="space-y-8">
      <div className="grid grid-cols-1 gap-8 lg:grid-cols-5">
        <div className="space-y-6 lg:col-span-3">
          <section
            className="rounded-2xl border border-cyan-300/30 bg-white p-5 shadow-xl shadow-cyan-950/20 sm:p-6"
            aria-labelledby="input-heading"
          >
            <div className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
              <div>
                <label
                  id="input-heading"
                  htmlFor={inputId}
                  className="block text-sm font-semibold text-slate-900"
                >
                  Input AI Prompt / System Context / MCP Payload
                </label>
                <p className="mt-1 text-xs text-slate-500">
                  Paste prompts, system instructions, agent context, tool
                  definitions, or conversation logs. Scanning stays in your
                  browser.
                </p>
              </div>
              <p className="rounded-full bg-cyan-50 px-2.5 py-1 text-xs font-semibold tabular-nums text-cyan-800" aria-live="polite">
                {characterCount.toLocaleString()} characters
              </p>
            </div>

            <textarea
              id={inputId}
              value={input}
              onChange={(event) => {
                setInput(event.target.value);
                setActivePresetId(null);
                setHasScanned(false);
                setResult(null);
                setError(null);
              }}
              rows={14}
              spellCheck={false}
              className="mt-3 w-full resize-y rounded-xl border border-slate-200 bg-gradient-to-br from-slate-50 to-cyan-50/40 px-3 py-3 font-mono text-sm leading-relaxed text-slate-900 shadow-inner transition placeholder:text-slate-400 focus:border-cyan-500 focus:bg-white focus:outline-none focus:ring-2 focus:ring-cyan-500/30"
              placeholder="Paste an AI prompt, system instruction block, or MCP payload…"
              aria-describedby="input-help"
            />
            <p id="input-help" className="sr-only">
              Your prompt data never leaves your browser.
            </p>

            <div className="mt-4 flex flex-wrap gap-2">
              <button
                type="button"
                onClick={runScan}
                disabled={isEmpty || isPending}
                className="inline-flex items-center justify-center rounded-full bg-gradient-to-r from-cyan-500 via-teal-500 to-emerald-500 px-5 py-2.5 text-sm font-bold text-white shadow-lg shadow-teal-500/30 transition hover:brightness-110 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-cyan-500 disabled:cursor-not-allowed disabled:opacity-50"
              >
                {isPending ? "Scanning…" : "Scan Prompt"}
              </button>
              <button
                type="button"
                onClick={handleLoadSample}
                className="rounded-full border border-amber-300 bg-amber-50 px-4 py-2.5 text-sm font-semibold text-amber-900 transition hover:bg-amber-100 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-amber-500"
              >
                Load Sample
              </button>
              <button
                type="button"
                onClick={handleClear}
                className="rounded-full border border-slate-300 bg-white px-4 py-2.5 text-sm font-semibold text-slate-700 transition hover:bg-slate-50 focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-slate-500"
              >
                Clear
              </button>
            </div>

            {error && (
              <p className="mt-3 text-sm font-medium text-rose-700" role="alert">
                {error}
              </p>
            )}
          </section>

          <PresetAttacks
            presets={ATTACK_PRESETS}
            activeId={activePresetId}
            onSelect={handlePreset}
          />

          {hasScanned && result && findings.length > 0 && (
            <section
              className="rounded-2xl border border-rose-300/40 bg-white p-5 shadow-xl shadow-rose-950/10 sm:p-6"
              aria-labelledby="highlight-heading"
            >
              <h2
                id="highlight-heading"
                className="text-sm font-semibold text-slate-900"
              >
                Highlighted Matches in Original Input
              </h2>
              <p className="mt-1 text-xs text-slate-500">
                Matched ranges are highlighted by severity. Original text is
                preserved and escaped as plain text.
              </p>
              <div className="mt-3 max-h-72 overflow-auto rounded-xl border border-slate-200 bg-slate-50 p-3 text-slate-900">
                <HighlightedText text={input} findings={highlightFindings} />
              </div>
            </section>
          )}
        </div>

        <div className="space-y-6 lg:col-span-2">
          <RiskScore
            result={result}
            hasScanned={hasScanned}
            isEmpty={isEmpty}
          />
          <ThreatBreakdown
            findings={findings}
            hasScanned={hasScanned}
            onExportJson={exportJson}
            onExportMarkdown={exportMarkdown}
          />
          <HardenedOutput
            sanitizedPrompt={result?.sanitizedPrompt ?? ""}
            hasScanned={hasScanned}
          />
        </div>
      </div>
    </div>
  );
}
