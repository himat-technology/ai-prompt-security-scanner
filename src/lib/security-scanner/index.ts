import type {
  CategoryBreakdown,
  ScanResult,
  ThreatFinding,
} from "./types";
import {
  EMPTY_CATEGORY_BREAKDOWN,
  SCANNER_TOOL_NAME,
  SCANNER_VERSION,
} from "./types";
import { detectPromptInjection } from "./rules/prompt-injection";
import { detectJailbreak } from "./rules/jailbreak";
import { detectSystemExtraction } from "./rules/system-extraction";
import { detectSecrets } from "./rules/secrets";
import { detectPii } from "./rules/pii";
import { detectExfiltration } from "./rules/exfiltration";
import { detectObfuscation } from "./rules/obfuscation";
import { detectIndirectInjection } from "./rules/indirect-injection";
import { sanitizePrompt, toAuditFindings } from "./sanitizer";
import { computeRiskScore, scoreToSeverity } from "./scorer";
import { dedupeFindings } from "./utils";

export * from "./types";
export * from "./presets";
export { sanitizePrompt, toAuditFindings } from "./sanitizer";
export { computeRiskScore, scoreToSeverity } from "./scorer";
export { redactSecretDisplay } from "./rules/secrets";

function buildCategoryBreakdown(findings: ThreatFinding[]): CategoryBreakdown {
  const breakdown: CategoryBreakdown = { ...EMPTY_CATEGORY_BREAKDOWN };
  for (const finding of findings) {
    breakdown[finding.category] += 1;
  }
  return breakdown;
}

function countWords(input: string): number {
  const trimmed = input.trim();
  if (!trimmed) return 0;
  return trimmed.split(/\s+/).length;
}

/**
 * Run the full local, deterministic security scan.
 * No network I/O. Safe to call from the browser.
 */
export function scanPrompt(input: string): ScanResult {
  const text = input ?? "";

  if (!text.trim()) {
    return {
      riskScore: 0,
      severity: "low",
      findings: [],
      categoryBreakdown: { ...EMPTY_CATEGORY_BREAKDOWN },
      sanitizedPrompt: "",
      statistics: {
        characterCount: 0,
        findingCount: 0,
        categoriesDetected: 0,
        wordCount: 0,
      },
    };
  }

  const rawFindings: ThreatFinding[] = [
    ...detectPromptInjection(text),
    ...detectJailbreak(text),
    ...detectSystemExtraction(text),
    ...detectSecrets(text),
    ...detectPii(text),
    ...detectExfiltration(text),
    ...detectObfuscation(text),
    ...detectIndirectInjection(text),
  ];

  const findings = dedupeFindings(rawFindings);
  const riskScore = computeRiskScore(findings);
  const severity = scoreToSeverity(riskScore);
  const categoryBreakdown = buildCategoryBreakdown(findings);
  const sanitizedPrompt = sanitizePrompt(text, { findings, wrapUntrusted: true });
  const categoriesDetected = Object.values(categoryBreakdown).filter(
    (n) => n > 0
  ).length;

  return {
    riskScore,
    severity,
    findings,
    categoryBreakdown,
    sanitizedPrompt,
    statistics: {
      characterCount: text.length,
      findingCount: findings.length,
      categoriesDetected,
      wordCount: countWords(text),
    },
  };
}

export interface AuditReport {
  tool: string;
  version: string;
  timestamp: string;
  riskScore: number;
  severity: string;
  findings: ThreatFinding[];
  categoryBreakdown: CategoryBreakdown;
  sanitizedPrompt: string;
  statistics: ScanResult["statistics"];
}

/** Build a downloadable audit JSON object with secrets already redacted. */
export function buildAuditReport(result: ScanResult): AuditReport {
  return {
    tool: SCANNER_TOOL_NAME,
    version: SCANNER_VERSION,
    timestamp: new Date().toISOString(),
    riskScore: result.riskScore,
    severity: result.severity,
    findings: toAuditFindings(result.findings),
    categoryBreakdown: result.categoryBreakdown,
    sanitizedPrompt: result.sanitizedPrompt,
    statistics: result.statistics,
  };
}

/** Build a Markdown audit report (secrets already redacted). */
export function buildMarkdownReport(result: ScanResult): string {
  const audit = buildAuditReport(result);
  const lines: string[] = [
    `# ${audit.tool}`,
    "",
    `- **Version:** ${audit.version}`,
    `- **Timestamp:** ${audit.timestamp}`,
    `- **Risk Score:** ${audit.riskScore} / 100`,
    `- **Severity:** ${audit.severity}`,
    `- **Threat Vectors:** ${audit.findings.length}`,
    "",
    "## Category Breakdown",
    "",
  ];

  for (const [category, count] of Object.entries(audit.categoryBreakdown)) {
    if (count > 0) {
      lines.push(`- **${category}:** ${count}`);
    }
  }

  if (audit.findings.length === 0) {
    lines.push("", "No security threats detected.");
  } else {
    lines.push("", "## Findings", "");
    audit.findings.forEach((finding, index) => {
      lines.push(
        `### ${index + 1}. ${finding.title}`,
        "",
        `- **Severity:** ${finding.severity}`,
        `- **Category:** ${finding.category}`,
        `- **Matched:** \`${finding.displaySnippet ?? finding.matchedSnippet}\``,
        "",
        finding.description,
        "",
        `**Recommendation:** ${finding.recommendation}`,
        ""
      );
    });
  }

  lines.push(
    "## Sanitized Prompt",
    "",
    "```",
    audit.sanitizedPrompt || "(empty)",
    "```",
    ""
  );

  return lines.join("\n");
}
