"use client";

import { buildHighlightSegments, severityHighlightClass } from "@/lib/highlight";
import type { ThreatFinding } from "@/lib/security-scanner";

interface HighlightedTextProps {
  text: string;
  findings: ThreatFinding[];
  className?: string;
}

export function HighlightedText({
  text,
  findings,
  className = "",
}: HighlightedTextProps) {
  const segments = buildHighlightSegments(text, findings);

  return (
    <pre
      className={`whitespace-pre-wrap break-words font-mono text-sm leading-relaxed ${className}`}
      aria-label="Prompt text with highlighted security matches"
    >
      {segments.map((segment, index) =>
        segment.findingIds.length > 0 ? (
          <mark
            key={`${index}-${segment.findingIds.join("-")}`}
            className={`rounded-sm px-0.5 ${severityHighlightClass(segment.maxSeverity)}`}
            title={`${segment.findingIds.length} finding(s)`}
          >
            {segment.text}
          </mark>
        ) : (
          <span key={index}>{segment.text}</span>
        )
      )}
    </pre>
  );
}
