import type { DetectionRule } from "../types";
import { SEVERITY_WEIGHTS } from "../types";
import { runRules } from "../utils";

/** Redact secrets for display: keep a short prefix, never the full value. */
export function redactSecretDisplay(secret: string): string {
  const trimmed = secret.trim();
  if (trimmed.length <= 8) {
    return `${trimmed.slice(0, 2)}…[REDACTED]`;
  }

  // Preserve scheme for connection strings
  const schemeMatch = trimmed.match(/^((?:postgres(?:ql)?|mongodb(?:\+srv)?|mysql|redis|amqp):\/\/)/i);
  if (schemeMatch) {
    return `${schemeMatch[1]}…[REDACTED]`;
  }

  // Bearer tokens
  if (/^bearer\s+/i.test(trimmed)) {
    return `Bearer …[REDACTED]`;
  }

  // Key=value forms
  const kv = trimmed.match(/^([a-zA-Z0-9_.-]+\s*[=:]\s*)(.+)$/);
  if (kv) {
    const prefix = kv[2].slice(0, 4);
    return `${kv[1]}${prefix}…[REDACTED]`;
  }

  const prefix = trimmed.slice(0, Math.min(8, Math.floor(trimmed.length / 3)));
  return `${prefix}…[REDACTED]`;
}

export function redactSecretPlaceholder(secret: string): string {
  if (/^(?:postgres(?:ql)?|mongodb(?:\+srv)?|mysql|redis|amqp):\/\//i.test(secret)) {
    return "[REDACTED_CONNECTION_STRING]";
  }
  if (/^bearer\s+/i.test(secret)) {
    return "Bearer [REDACTED_TOKEN]";
  }
  if (/\b(api[_-]?key|apikey|secret|token)\s*[=:]/i.test(secret)) {
    return secret.replace(
      /^([a-zA-Z0-9_.-]+\s*[=:]\s*).+$/i,
      "$1[REDACTED_API_KEY]"
    );
  }
  return "[REDACTED_API_KEY]";
}

const RULES: DetectionRule[] = [
  {
    id: "openai-key",
    category: "secret-exposure",
    severity: "critical",
    title: "API Key Exposure (OpenAI-style)",
    description: "Detected an OpenAI-style secret key pattern (sk-…).",
    recommendation:
      "Rotate the key immediately and never embed secrets in prompts or logs.",
    scoreContribution: SEVERITY_WEIGHTS.critical,
    pattern: /\bsk-[A-Za-z0-9_-]{16,}\b/g,
    formatMatch: redactSecretDisplay,
  },
  {
    id: "github-pat",
    category: "secret-exposure",
    severity: "critical",
    title: "GitHub Token Exposure",
    description: "Detected a GitHub personal access token pattern.",
    recommendation:
      "Revoke the token in GitHub settings and use short-lived secrets via a vault.",
    scoreContribution: SEVERITY_WEIGHTS.critical,
    pattern: /\b(?:ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/g,
    formatMatch: redactSecretDisplay,
  },
  {
    id: "aws-key",
    category: "secret-exposure",
    severity: "critical",
    title: "AWS Access Key Exposure",
    description: "Detected an AWS access key ID pattern (AKIA…).",
    recommendation:
      "Rotate the AWS key and remove it from prompts, tickets, and chat logs.",
    scoreContribution: SEVERITY_WEIGHTS.critical,
    pattern: /\bAKIA[0-9A-Z]{16}\b/g,
    formatMatch: redactSecretDisplay,
  },
  {
    id: "bearer-token",
    category: "secret-exposure",
    severity: "high",
    title: "Bearer Token Exposure",
    description: "Detected a Bearer authorization token in the prompt text.",
    recommendation:
      "Remove authorization headers/tokens from prompt context before sharing.",
    scoreContribution: SEVERITY_WEIGHTS.high,
    pattern: /\bBearer\s+[A-Za-z0-9\-._~+/]+=*/g,
    formatMatch: redactSecretDisplay,
  },
  {
    id: "generic-api-key",
    category: "secret-exposure",
    severity: "high",
    title: "Generic API Key / Secret Assignment",
    description:
      "Detected an api_key / secret / token assignment that may expose credentials.",
    recommendation:
      "Replace inline credentials with environment variables or secret references.",
    scoreContribution: SEVERITY_WEIGHTS.high,
    pattern:
      /\b(?:api[_-]?key|apikey|secret|access[_-]?token|auth[_-]?token|token)\s*[=:]\s*['"]?[A-Za-z0-9_\-./+=]{8,}['"]?/gi,
    formatMatch: redactSecretDisplay,
    validate: (match) => {
      const value = match[0];
      // Skip obvious placeholders
      if (/\[REDACTED|YOUR_|EXAMPLE|PLACEHOLDER|xxx+|<.*>/i.test(value)) {
        return false;
      }
      return true;
    },
  },
  {
    id: "db-connection",
    category: "secret-exposure",
    severity: "critical",
    title: "Database Connection String Exposure",
    description:
      "Detected a database connection URI that may contain credentials.",
    recommendation:
      "Redact connection strings and store credentials in a secrets manager.",
    scoreContribution: SEVERITY_WEIGHTS.critical,
    pattern:
      /\b(?:postgres(?:ql)?|mongodb(?:\+srv)?|mysql|redis|amqp):\/\/[^\s"'<>]+/gi,
    formatMatch: redactSecretDisplay,
  },
];

export function detectSecrets(input: string) {
  return runRules(input, RULES, "sec");
}
