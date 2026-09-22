import type { ThreatFinding } from "@/lib/security-scanner";

export interface HighlightSegment {
  text: string;
  findingIds: string[];
  maxSeverity?: ThreatFinding["severity"];
}

const SEVERITY_RANK: Record<ThreatFinding["severity"], number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

/**
 * Split input into segments with associated finding IDs.
 * Handles overlapping ranges safely without HTML injection.
 */
export function buildHighlightSegments(
  input: string,
  findings: ThreatFinding[]
): HighlightSegment[] {
  if (!input) return [];
  if (findings.length === 0) return [{ text: input, findingIds: [] }];

  const points = new Set<number>([0, input.length]);
  for (const f of findings) {
    const start = Math.max(0, Math.min(input.length, f.startIndex));
    const end = Math.max(start, Math.min(input.length, f.endIndex));
    points.add(start);
    points.add(end);
  }

  const sorted = Array.from(points).sort((a, b) => a - b);
  const segments: HighlightSegment[] = [];

  for (let i = 0; i < sorted.length - 1; i += 1) {
    const start = sorted[i];
    const end = sorted[i + 1];
    if (start === end) continue;

    const covering = findings.filter(
      (f) => f.startIndex < end && f.endIndex > start
    );

    let maxSeverity: ThreatFinding["severity"] | undefined;
    for (const f of covering) {
      if (
        !maxSeverity ||
        SEVERITY_RANK[f.severity] > SEVERITY_RANK[maxSeverity]
      ) {
        maxSeverity = f.severity;
      }
    }

    segments.push({
      text: input.slice(start, end),
      findingIds: covering.map((f) => f.id),
      maxSeverity,
    });
  }

  return segments;
}

export function severityHighlightClass(
  severity?: ThreatFinding["severity"]
): string {
  switch (severity) {
    case "critical":
      return "bg-red-200/90 text-red-950 outline outline-1 outline-red-400";
    case "high":
      return "bg-orange-200/90 text-orange-950 outline outline-1 outline-orange-400";
    case "medium":
      return "bg-amber-200/80 text-amber-950 outline outline-1 outline-amber-400";
    case "low":
      return "bg-sky-200/80 text-sky-950 outline outline-1 outline-sky-400";
    default:
      return "";
  }
}
