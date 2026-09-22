export type ThreatSeverity = "critical" | "high" | "medium" | "low";

export type ThreatCategory =
  | "prompt-injection"
  | "jailbreak"
  | "system-extraction"
  | "secret-exposure"
  | "pii"
  | "data-exfiltration"
  | "obfuscation"
  | "indirect-injection";

export interface ThreatFinding {
  id: string;
  category: ThreatCategory;
  severity: ThreatSeverity;
  title: string;
  description: string;
  matchedSnippet: string;
  startIndex: number;
  endIndex: number;
  recommendation: string;
  scoreContribution: number;
  /** Display-safe snippet with secrets already redacted */
  displaySnippet?: string;
}

export interface CategoryBreakdown {
  "prompt-injection": number;
  jailbreak: number;
  "system-extraction": number;
  "secret-exposure": number;
  pii: number;
  "data-exfiltration": number;
  obfuscation: number;
  "indirect-injection": number;
}

export interface ScanStatistics {
  characterCount: number;
  findingCount: number;
  categoriesDetected: number;
  wordCount: number;
}

export interface ScanResult {
  riskScore: number;
  severity: ThreatSeverity;
  findings: ThreatFinding[];
  categoryBreakdown: CategoryBreakdown;
  sanitizedPrompt: string;
  statistics: ScanStatistics;
}

export interface DetectionRule {
  id: string;
  category: ThreatCategory;
  severity: ThreatSeverity;
  title: string;
  description: string;
  recommendation: string;
  scoreContribution: number;
  pattern: RegExp;
  /** Optional post-filter to reduce false positives */
  validate?: (match: RegExpMatchArray, input: string) => boolean;
  /** Transform matched text for display (e.g. redact secrets) */
  formatMatch?: (matched: string) => string;
}

export interface AttackPreset {
  id: string;
  label: string;
  description: string;
  sample: string;
}

export const SEVERITY_WEIGHTS: Record<ThreatSeverity, number> = {
  critical: 40,
  high: 25,
  medium: 15,
  low: 5,
};

export const EMPTY_CATEGORY_BREAKDOWN: CategoryBreakdown = {
  "prompt-injection": 0,
  jailbreak: 0,
  "system-extraction": 0,
  "secret-exposure": 0,
  pii: 0,
  "data-exfiltration": 0,
  obfuscation: 0,
  "indirect-injection": 0,
};

export const CATEGORY_LABELS: Record<ThreatCategory, string> = {
  "prompt-injection": "Direct Injection",
  jailbreak: "Jailbreak",
  "system-extraction": "System Extraction",
  "secret-exposure": "Secret Exposure",
  pii: "PII Exposure",
  "data-exfiltration": "Data Exfiltration",
  obfuscation: "Obfuscation",
  "indirect-injection": "Indirect Injection",
};

export const SEVERITY_LABELS: Record<ThreatSeverity, string> = {
  critical: "Critical Risk",
  high: "High Risk",
  medium: "Moderate Risk",
  low: "Low Risk",
};

export const SCANNER_VERSION = "1.0.0";
export const SCANNER_TOOL_NAME = "AI Prompt Security & Injection Scanner";
