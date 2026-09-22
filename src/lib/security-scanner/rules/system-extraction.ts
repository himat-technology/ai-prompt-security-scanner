import type { DetectionRule } from "../types";
import { SEVERITY_WEIGHTS } from "../types";
import { runRules } from "../utils";

const RULES: DetectionRule[] = [
  {
    id: "reveal-system-prompt",
    category: "system-extraction",
    severity: "critical",
    title: "System Prompt Extraction Attempt",
    description:
      "Attempts to reveal hidden system prompts, developer instructions, or confidential context.",
    recommendation:
      "Block extraction phrases and never echo system prompts into model outputs.",
    scoreContribution: SEVERITY_WEIGHTS.critical,
    pattern:
      /\b(?:reveal|show|print|display|disclose|output|repeat|dump)\s+(?:me\s+)?(?:your\s+)?(?:the\s+)?(?:hidden\s+|secret\s+|confidential\s+|internal\s+|full\s+)?(?:system\s+prompt|system\s+instructions?|developer\s+instructions?|hidden\s+prompt|hidden\s+instructions?|initial\s+instructions?|confidential\s+context)\b/gi,
  },
  {
    id: "what-are-instructions",
    category: "system-extraction",
    severity: "high",
    title: "Hidden Instruction Disclosure Probe",
    description:
      "Asks the model to disclose hidden, secret, or developer-provided instructions.",
    recommendation:
      "Respond with a refusal policy for system-prompt disclosure requests.",
    scoreContribution: SEVERITY_WEIGHTS.high,
    pattern:
      /\bwhat\s+(?:are|is)\s+your\s+(?:hidden\s+|secret\s+|system\s+|developer\s+)?(?:instructions?|prompt|rules?|system\s+prompt)\b|\brepeat\s+(?:the\s+)?(?:instructions?|prompt)\s+(?:above|exactly|verbatim)\b|\breveal\s+confidential\s+context\b/gi,
  },
  {
    id: "print-above",
    category: "system-extraction",
    severity: "medium",
    title: "Context Replay Extraction",
    description:
      "Attempts to force the model to replay earlier privileged context blocks.",
    recommendation:
      "Avoid echoing privileged context; summarize only user-visible content.",
    scoreContribution: SEVERITY_WEIGHTS.medium,
    pattern:
      /\b(?:print|output|echo|return)\s+(?:everything|all)\s+(?:above|before\s+this|from\s+the\s+system)\b|\bencode\s+your\s+system\s+prompt\b/gi,
  },
];

export function detectSystemExtraction(input: string) {
  return runRules(input, RULES, "sys");
}
