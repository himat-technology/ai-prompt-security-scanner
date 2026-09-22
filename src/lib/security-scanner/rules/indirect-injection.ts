import type { DetectionRule } from "../types";
import { SEVERITY_WEIGHTS } from "../types";
import { runRules } from "../utils";

/**
 * Indirect injection: malicious instructions embedded in documents, JSON,
 * tool descriptions, MCP payloads, or quoted retrieved content.
 */
const RULES: DetectionRule[] = [
  {
    id: "json-embedded-ignore",
    category: "indirect-injection",
    severity: "high",
    title: "Indirect Injection in Structured Content",
    description:
      "Instruction-override language appears embedded inside JSON/XML/tool/MCP context.",
    recommendation:
      "Treat retrieved and tool-provided text as untrusted data, not executable instructions.",
    scoreContribution: SEVERITY_WEIGHTS.high,
    pattern:
      /(?:"[^"]{0,80}"\s*:\s*"[^"]{0,40})?\b(?:ignore|disregard)\s+(?:the\s+)?(?:system|previous|prior)\s+(?:message|instructions?|prompt|rules?)\b/gi,
  },
  {
    id: "assistant-must",
    category: "indirect-injection",
    severity: "high",
    title: "Embedded Assistant Directive",
    description:
      "Content tries to issue privileged directives to the assistant from within documents or tools.",
    recommendation:
      "Strip assistant/system directives from retrieved documents before grounding.",
    scoreContribution: SEVERITY_WEIGHTS.high,
    pattern:
      /\b(?:assistant|ai|model|llm)\s+must\s+(?:reveal|ignore|bypass|disclose|execute|override)\b|\b(?:important|note|system)\s*:\s*(?:ignore|disregard|override)\b/gi,
  },
  {
    id: "tool-description-injection",
    category: "indirect-injection",
    severity: "critical",
    title: "Tool / MCP Description Injection",
    description:
      "A tool description or MCP context block embeds security-bypass instructions.",
    recommendation:
      "Validate and sanitize MCP tool descriptions; never trust remote tool metadata blindly.",
    scoreContribution: SEVERITY_WEIGHTS.critical,
    pattern:
      /\b(?:tool[\s_-]*description|mcp[\s_-]*(?:context|server|tool)|function[\s_-]*description)\s*:?[^\n]{0,120}\b(?:ignore|bypass|reveal|override|disregard)\b/gi,
  },
  {
    id: "quoted-hidden-instruction",
    category: "indirect-injection",
    severity: "medium",
    title: "Quoted Hidden Instruction",
    description:
      "Quoted or document-embedded text contains likely malicious instruction phrases.",
    recommendation:
      "Distinguish cited text from instructions; wrap retrieved content in data delimiters.",
    scoreContribution: SEVERITY_WEIGHTS.medium,
    pattern:
      /(?:"|“|'|‘)[^"'“”‘’]{0,20}\b(?:ignore\s+(?:all\s+)?(?:previous|prior|system)\s+instructions?|reveal\s+your\s+system\s+prompt)\b[^"'“”‘’]{0,40}(?:"|”|'|’)/gi,
  },
  {
    id: "xml-cdata-injection",
    category: "indirect-injection",
    severity: "high",
    title: "XML / Markup Embedded Injection",
    description:
      "Markup or XML-like content embeds instruction override attempts.",
    recommendation:
      "Parse markup as data only; do not promote nested text into the system role.",
    scoreContribution: SEVERITY_WEIGHTS.high,
    pattern:
      /<(?:document|content|context|data|retrieved|tool)[^>]*>[^<]{0,40}\b(?:ignore|disregard|override)\s+(?:all\s+)?(?:previous|system)\b/gi,
  },
];

export function detectIndirectInjection(input: string) {
  return runRules(input, RULES, "ind");
}
