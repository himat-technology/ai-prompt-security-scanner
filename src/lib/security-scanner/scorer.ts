import type { ThreatFinding, ThreatSeverity } from "./types";
import { SEVERITY_WEIGHTS } from "./types";

const SEVERITY_RANK: Record<ThreatSeverity, number> = {
  low: 0,
  medium: 1,
  high: 2,
  critical: 3,
};

/**
 * Deterministic weighted risk score (0–100).
 * Uses severity weights with diminishing returns for repeated identical titles
 * to avoid excessive double-counting of the same attack pattern.
 */
export function computeRiskScore(findings: ThreatFinding[]): number {
  if (findings.length === 0) return 0;

  const titleCounts = new Map<string, number>();
  let score = 0;

  for (const finding of findings) {
    const key = `${finding.category}:${finding.title}`;
    const seen = titleCounts.get(key) ?? 0;
    titleCounts.set(key, seen + 1);

    const base =
      finding.scoreContribution || SEVERITY_WEIGHTS[finding.severity];

    // First match: full weight; subsequent identical titles: 40%, then 20%
    const multiplier = seen === 0 ? 1 : seen === 1 ? 0.4 : 0.2;
    score += base * multiplier;
  }

  return Math.min(100, Math.round(score));
}

export function scoreToSeverity(score: number): ThreatSeverity {
  if (score >= 70) return "critical";
  if (score >= 40) return "high";
  if (score >= 20) return "medium";
  return "low";
}

export function maxFindingSeverity(
  findings: ThreatFinding[]
): ThreatSeverity | null {
  if (findings.length === 0) return null;
  return findings.reduce<ThreatSeverity>((max, f) => {
    return SEVERITY_RANK[f.severity] > SEVERITY_RANK[max] ? f.severity : max;
  }, "low");
}
