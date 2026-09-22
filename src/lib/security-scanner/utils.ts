import type { DetectionRule, ThreatFinding } from "./types";

/** Escape special regex characters in a literal string. */
export function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Clip a snippet for safe display (never returns raw long secrets). */
export function clipSnippet(text: string, maxLength = 120): string {
  const normalized = text.replace(/\s+/g, " ").trim();
  if (normalized.length <= maxLength) return normalized;
  return `${normalized.slice(0, maxLength - 1)}…`;
}

/**
 * Run a list of detection rules against input and produce findings.
 * Patterns should be compiled with the global flag when multiple matches are expected.
 */
export function runRules(
  input: string,
  rules: DetectionRule[],
  idPrefix: string
): ThreatFinding[] {
  const findings: ThreatFinding[] = [];

  for (const rule of rules) {
    const pattern = ensureGlobal(rule.pattern);
    pattern.lastIndex = 0;

    let match: RegExpExecArray | null;
    let matchIndex = 0;

    while ((match = pattern.exec(input)) !== null) {
      if (match[0].length === 0) {
        pattern.lastIndex += 1;
        continue;
      }

      if (rule.validate && !rule.validate(match, input)) {
        continue;
      }

      const matchedSnippet = match[0];
      const startIndex = match.index;
      const endIndex = startIndex + matchedSnippet.length;
      const displaySnippet = rule.formatMatch
        ? rule.formatMatch(matchedSnippet)
        : clipSnippet(matchedSnippet);

      findings.push({
        id: `${idPrefix}-${rule.id}-${matchIndex}-${startIndex}`,
        category: rule.category,
        severity: rule.severity,
        title: rule.title,
        description: rule.description,
        matchedSnippet: clipSnippet(matchedSnippet),
        displaySnippet,
        startIndex,
        endIndex,
        recommendation: rule.recommendation,
        scoreContribution: rule.scoreContribution,
      });

      matchIndex += 1;

      // Guard against pathological zero-width loops
      if (matchIndex > 200) break;
    }
  }

  return findings;
}

function ensureGlobal(pattern: RegExp): RegExp {
  if (pattern.global) return pattern;
  return new RegExp(
    pattern.source,
    `${pattern.flags}g`
  );
}

/** Deduplicate overlapping identical category+title matches that share the same span. */
export function dedupeFindings(findings: ThreatFinding[]): ThreatFinding[] {
  const seen = new Set<string>();
  const result: ThreatFinding[] = [];

  for (const finding of findings) {
    const key = `${finding.category}|${finding.title}|${finding.startIndex}|${finding.endIndex}`;
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(finding);
  }

  return result.sort((a, b) => a.startIndex - b.startIndex || b.scoreContribution - a.scoreContribution);
}
