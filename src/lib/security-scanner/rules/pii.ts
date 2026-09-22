import type { DetectionRule } from "../types";
import { SEVERITY_WEIGHTS } from "../types";
import { runRules } from "../utils";

/** Luhn check for credit card numbers to reduce false positives. */
export function luhnCheck(digits: string): boolean {
  const cleaned = digits.replace(/\D/g, "");
  if (cleaned.length < 13 || cleaned.length > 19) return false;

  let sum = 0;
  let alternate = false;
  for (let i = cleaned.length - 1; i >= 0; i -= 1) {
    let n = Number(cleaned[i]);
    if (alternate) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    alternate = !alternate;
  }
  return sum % 10 === 0;
}

export function redactPiiDisplay(value: string, kind: string): string {
  const trimmed = value.trim();
  switch (kind) {
    case "email": {
      const [user, domain] = trimmed.split("@");
      if (!domain) return "[REDACTED_EMAIL]";
      const visible = user.slice(0, Math.min(2, user.length));
      return `${visible}…@${domain}`;
    }
    case "phone":
      return `${trimmed.slice(0, 3)}…[REDACTED]`;
    case "ssn":
      return "***-**-" + trimmed.replace(/\D/g, "").slice(-4);
    case "cc":
      return `****-****-****-${trimmed.replace(/\D/g, "").slice(-4)}`;
    case "ip":
      return trimmed.replace(/(\d+\.\d+)\.\d+\.\d+/, "$1.x.x");
    default:
      return `${trimmed.slice(0, 4)}…[REDACTED]`;
  }
}

const RULES: DetectionRule[] = [
  {
    id: "email",
    category: "pii",
    severity: "medium",
    title: "Email Address Detected",
    description:
      "An email address appears in the prompt and may constitute PII exposure.",
    recommendation:
      "Redact or tokenize email addresses before sending prompts to external models.",
    scoreContribution: SEVERITY_WEIGHTS.medium,
    pattern: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
    formatMatch: (m) => redactPiiDisplay(m, "email"),
    validate: (match) => {
      // Skip common example domains
      return !/@(?:example\.(?:com|org|net)|test\.com|localhost)\b/i.test(
        match[0]
      );
    },
  },
  {
    id: "phone",
    category: "pii",
    severity: "medium",
    title: "Phone Number Detected",
    description: "A phone-number-like pattern was found in the prompt text.",
    recommendation:
      "Remove or mask phone numbers unless they are required for the task.",
    scoreContribution: SEVERITY_WEIGHTS.medium,
    // US-centric and international-ish; conservative to reduce FPs
    pattern:
      /(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}\b/g,
    formatMatch: (m) => redactPiiDisplay(m, "phone"),
    validate: (match) => {
      const digits = match[0].replace(/\D/g, "");
      // Require 10–15 digits; skip obvious sequences
      if (digits.length < 10 || digits.length > 15) return false;
      if (/^(\d)\1+$/.test(digits)) return false;
      if (/^(?:1234567890|0123456789)$/.test(digits)) return false;
      return true;
    },
  },
  {
    id: "credit-card",
    category: "pii",
    severity: "critical",
    title: "Credit Card Number Detected",
    description:
      "A Luhn-valid credit card number pattern was detected in the prompt.",
    recommendation:
      "Never include payment card data in prompts. Remove and rotate if exposed.",
    scoreContribution: SEVERITY_WEIGHTS.critical,
    pattern: /\b(?:\d[ -]*?){13,19}\b/g,
    formatMatch: (m) => redactPiiDisplay(m, "cc"),
    validate: (match) => luhnCheck(match[0]),
  },
  {
    id: "ssn",
    category: "pii",
    severity: "critical",
    title: "SSN-like Pattern Detected",
    description: "A Social Security Number-like pattern was found.",
    recommendation:
      "Remove SSN-like values immediately. Do not send government IDs to LLMs.",
    scoreContribution: SEVERITY_WEIGHTS.critical,
    pattern: /\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b/g,
    formatMatch: (m) => redactPiiDisplay(m, "ssn"),
    validate: (match, input) => {
      // Prefer context hints to reduce false positives on random digit groups
      const start = Math.max(0, match.index! - 30);
      const end = Math.min(input.length, match.index! + match[0].length + 30);
      const window = input.slice(start, end).toLowerCase();
      const hasHint =
        /\b(ssn|social\s*security|tax\s*id|itin)\b/i.test(window) ||
        /^\d{3}-\d{2}-\d{4}$/.test(match[0]);
      return hasHint;
    },
  },
  {
    id: "ipv4",
    category: "pii",
    severity: "low",
    title: "IP Address Detected",
    description: "An IPv4 address appears in the prompt context.",
    recommendation:
      "Mask internal IP addresses when sharing prompts outside your network.",
    scoreContribution: SEVERITY_WEIGHTS.low,
    pattern:
      /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g,
    formatMatch: (m) => redactPiiDisplay(m, "ip"),
    validate: (match) => {
      // Skip 0.0.0.0 and documentation ranges often used as examples
      if (match[0] === "0.0.0.0" || match[0] === "127.0.0.1") return false;
      if (/^192\.0\.2\./.test(match[0])) return false;
      return true;
    },
  },
  {
    id: "sensitive-url-params",
    category: "pii",
    severity: "medium",
    title: "Sensitive URL Parameter Detected",
    description:
      "A URL contains query parameters that may expose tokens, secrets, or personal data.",
    recommendation:
      "Strip sensitive query parameters before including URLs in prompts.",
    scoreContribution: SEVERITY_WEIGHTS.medium,
    pattern:
      /https?:\/\/[^\s"'<>]+[?&](?:access_token|token|key|api_key|password|secret|auth|session|ssn|email)=[^\s"'<>&]+/gi,
    formatMatch: (m) => `${m.slice(0, 40)}…[REDACTED]`,
  },
];

export function detectPii(input: string) {
  return runRules(input, RULES, "pii");
}
