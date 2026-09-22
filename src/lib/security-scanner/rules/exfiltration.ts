import type { DetectionRule } from "../types";
import { SEVERITY_WEIGHTS } from "../types";
import { runRules } from "../utils";

const SUSPICIOUS_PARAMS =
  /[?&](?:data|prompt|token|key|secret|payload|exfil|leak|q|content|msg|message|input)=/i;

const RULES: DetectionRule[] = [
  {
    id: "markdown-image-exfil",
    category: "data-exfiltration",
    severity: "critical",
    title: "Markdown Image Data Exfiltration",
    description:
      "Suspicious markdown image syntax may exfiltrate prompt data via an external URL.",
    recommendation:
      "Remove untrusted markdown images and never allow model-rendered remote images from user content.",
    scoreContribution: SEVERITY_WEIGHTS.critical,
    pattern: /!\[[^\]]*\]\(\s*https?:\/\/[^)\s]+(?:\s+"[^"]*")?\s*\)/gi,
    validate: (match) => {
      const url = match[0];
      return (
        SUSPICIOUS_PARAMS.test(url) ||
        /(?:webhook|exfil|collect|steal|beacon|track)/i.test(url) ||
        /%[0-9A-Fa-f]{2}/.test(url)
      );
    },
  },
  {
    id: "external-image-request",
    category: "data-exfiltration",
    severity: "high",
    title: "External Image / Webhook Request",
    description:
      "Prompt requests loading an external image or webhook URL that could leak data.",
    recommendation:
      "Block automatic fetching of URLs found in untrusted prompt content.",
    scoreContribution: SEVERITY_WEIGHTS.high,
    pattern:
      /\b(?:fetch|load|request|get|post|send|exfiltrate|beacon)\b[^.\n]{0,40}\bhttps?:\/\/[^\s"'<>]+/gi,
  },
  {
    id: "webhook-url",
    category: "data-exfiltration",
    severity: "high",
    title: "Suspicious Webhook URL",
    description:
      "Detected a webhook-style URL often used for covert data exfiltration.",
    recommendation:
      "Do not invoke webhook URLs discovered inside prompts or tool outputs.",
    scoreContribution: SEVERITY_WEIGHTS.high,
    pattern:
      /https?:\/\/[^\s"'<>]*(?:webhook|hooks\.slack|discord\.com\/api\/webhooks|inbox|collect)[^\s"'<>]*/gi,
  },
  {
    id: "hidden-html",
    category: "data-exfiltration",
    severity: "medium",
    title: "Suspicious Hidden HTML",
    description:
      "Hidden or remote HTML elements may attempt covert data leakage.",
    recommendation:
      "Sanitize HTML from untrusted content; do not render or execute it.",
    scoreContribution: SEVERITY_WEIGHTS.medium,
    pattern:
      /<(?:img|iframe|script|link|object|embed)\b[^>]*(?:src|href)\s*=\s*['"]?https?:\/\/[^'">\s]+/gi,
  },
  {
    id: "encoded-url-payload",
    category: "data-exfiltration",
    severity: "medium",
    title: "Encoded URL Payload",
    description:
      "URL contains heavily encoded content that may hide exfiltrated prompt data.",
    recommendation:
      "Decode and inspect encoded URL payloads offline; do not auto-fetch them.",
    scoreContribution: SEVERITY_WEIGHTS.medium,
    pattern: /https?:\/\/[^\s"'<>]*%[0-9A-Fa-f]{2}(?:[^\s"'<>]*%[0-9A-Fa-f]{2}){3,}[^\s"'<>]*/g,
  },
];

export function detectExfiltration(input: string) {
  return runRules(input, RULES, "exfil");
}
