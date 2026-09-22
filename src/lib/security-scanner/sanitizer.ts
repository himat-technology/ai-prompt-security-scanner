import type { ThreatFinding } from "./types";
import { redactSecretPlaceholder } from "./rules/secrets";

const INJECTION_PHRASES: RegExp[] = [
  /\b(?:please\s+)?(?:ignore|disregard|forget|overlook|bypass)\s+(?:all\s+)?(?:(?:the|your|any|prior|previous|earlier|above)\s+)*(?:instructions?|rules?|prompts?|guidelines?|directives?|policies|constraints?|system\s+(?:prompt|message|instructions?|rules?))\b/gi,
  /\b(?:system|developer|admin|policy)\s+override\b/gi,
  /\boverride\s+(?:the\s+)?(?:system|developer|admin)?\s*(?:instructions?|rules?|prompt|policies)\b/gi,
  /\bdo\s+not\s+follow\s+(?:any\s+)?(?:previous|prior|earlier|system)\s+instructions?\b/gi,
  /\bact\s+as\s+if\s+(?:(?:all|any|the|your)\s+)?(?:previous|prior|earlier|system)?\s*instructions?\s+(?:don'?t|do\s+not|do\s+n't)\s+exist\b/gi,
  /\b(?:you\s+are\s+)?DAN\b|\bdo\s+anything\s+now\b|\bDAN\s+mode\b|\bjailbreak\s+mode\b/gi,
  /\b(?:enable\s+)?(?:developer|unrestricted|god|sudo)\s+mode\b/gi,
  /\bbypass\s+(?:all\s+)?(?:safety|content)?\s*(?:filters?|policies|guardrails|restrictions?)\b/gi,
  /\bignores?\s+safety\s+(?:policies|filters?|rules|guidelines)\b/gi,
  /\bpretend\s+you\s+have\s+no\s+rules\b/gi,
  /\bact\s+without\s+restrictions?\b/gi,
  /\broleplay\s+as\s+(?:an?\s+)?(?:unrestricted|uncensored|unfiltered|evil|jailbroken)\s+ai\b/gi,
  /\b(?:reveal|show|print|display|disclose)\s+(?:me\s+)?(?:your\s+)?(?:the\s+)?(?:hidden\s+|secret\s+|confidential\s+)?(?:system\s+prompt|system\s+instructions?|developer\s+instructions?|hidden\s+prompt)\b/gi,
];

const SECRET_PATTERNS: RegExp[] = [
  /\bsk-[A-Za-z0-9_-]{16,}\b/g,
  /\b(?:ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/g,
  /\bAKIA[0-9A-Z]{16}\b/g,
  /\bBearer\s+[A-Za-z0-9\-._~+/]+=*/g,
  /\b(?:api[_-]?key|apikey|secret|access[_-]?token|auth[_-]?token|token)\s*[=:]\s*['"]?[A-Za-z0-9_\-./+=]{8,}['"]?/gi,
  /\b(?:postgres(?:ql)?|mongodb(?:\+srv)?|mysql|redis|amqp):\/\/[^\s"'<>]+/gi,
];

const PII_PATTERNS: { pattern: RegExp; replacement: string }[] = [
  {
    pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    replacement: "[REDACTED_EMAIL]",
  },
  {
    pattern: /(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}\b/g,
    replacement: "[REDACTED_PHONE]",
  },
  {
    pattern: /\b(?!000|666|9\d{2})\d{3}-\d{2}-\d{4}\b/g,
    replacement: "[REDACTED_SSN]",
  },
];

const ZERO_WIDTH = /[\u200B\u200C\u200D\u2060\uFEFF\u180E]/g;

export interface SanitizeOptions {
  wrapUntrusted?: boolean;
  findings?: ThreatFinding[];
}

/**
 * Deterministic local sanitizer:
 * 1. Strip zero-width chars
 * 2. Redact secrets
 * 3. Redact PII
 * 4. Replace injection phrases
 * 5. Optionally wrap in <user_untrusted_input>
 */
export function sanitizePrompt(
  input: string,
  options: SanitizeOptions = {}
): string {
  const { wrapUntrusted = true } = options;
  let output = input.replace(ZERO_WIDTH, "");

  for (const pattern of SECRET_PATTERNS) {
    pattern.lastIndex = 0;
    output = output.replace(pattern, (matched) =>
      redactSecretPlaceholder(matched)
    );
  }

  // Credit cards (conservative: 13–19 digit runs with separators)
  output = output.replace(/\b(?:\d[ -]*?){13,19}\b/g, (matched) => {
    const digits = matched.replace(/\D/g, "");
    if (digits.length < 13 || digits.length > 19) return matched;
    // lightweight Luhn
    let sum = 0;
    let alt = false;
    for (let i = digits.length - 1; i >= 0; i -= 1) {
      let n = Number(digits[i]);
      if (alt) {
        n *= 2;
        if (n > 9) n -= 9;
      }
      sum += n;
      alt = !alt;
    }
    return sum % 10 === 0 ? "[REDACTED_CREDIT_CARD]" : matched;
  });

  for (const { pattern, replacement } of PII_PATTERNS) {
    pattern.lastIndex = 0;
    output = output.replace(pattern, replacement);
  }

  for (const pattern of INJECTION_PHRASES) {
    pattern.lastIndex = 0;
    output = output.replace(pattern, "[REDACTED_INJECTION_ATTEMPT]");
  }

  // Also redact secret spans reported by the scanner (already redacted display)
  if (options.findings) {
    for (const finding of options.findings) {
      if (
        finding.category === "secret-exposure" &&
        finding.matchedSnippet &&
        !finding.matchedSnippet.includes("[REDACTED")
      ) {
        // matchedSnippet may be clipped; skip unsafe raw replacement
        continue;
      }
    }
  }

  output = output.replace(/[ \t]+\n/g, "\n").replace(/\n{3,}/g, "\n\n").trim();

  if (!wrapUntrusted) return output;

  return `<user_untrusted_input>\n${output}\n</user_untrusted_input>`;
}

/** Build an audit-safe finding list with secrets already display-redacted. */
export function toAuditFindings(findings: ThreatFinding[]): ThreatFinding[] {
  return findings.map((f) => ({
    ...f,
    matchedSnippet: f.displaySnippet ?? f.matchedSnippet,
  }));
}
