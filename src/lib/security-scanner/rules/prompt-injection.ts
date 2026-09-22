import type { DetectionRule } from "../types";
import { SEVERITY_WEIGHTS } from "../types";
import { runRules } from "../utils";

const RULES: DetectionRule[] = [
  {
    id: "ignore-previous",
    category: "prompt-injection",
    severity: "critical",
    title: "Critical Instruction Override Attempt",
    description:
      "Attempts to force the LLM to ignore developer-provided system instructions.",
    recommendation:
      "Remove or sanitize instruction override verbs before passing untrusted input into model context.",
    scoreContribution: SEVERITY_WEIGHTS.critical,
    pattern:
      /\b(?:please\s+)?(?:ignore|disregard|forget|overlook|bypass)\s+(?:all\s+)?(?:(?:the|your|any|prior|previous|earlier|above)\s+)*(?:instructions?|rules?|prompts?|guidelines?|directives?|policies|constraints?|system\s+(?:prompt|message|instructions?|rules?))\b/gi,
  },
  {
    id: "override-system",
    category: "prompt-injection",
    severity: "critical",
    title: "System Override Injection",
    description:
      "Attempts to override system, developer, or policy instructions with new directives.",
    recommendation:
      "Strip override language and enforce system-prompt priority on the server side.",
    scoreContribution: SEVERITY_WEIGHTS.critical,
    pattern:
      /\b(?:system|developer|admin|policy)\s+override\b|\boverride\s+(?:the\s+)?(?:system|developer|admin)?\s*(?:instructions?|rules?|prompt|policies)\b|\bnew\s+instructions?\s*(?:are|follow|:)\b|\bdo\s+not\s+follow\s+(?:any\s+)?(?:previous|prior|earlier|system)\s+instructions?\b/gi,
  },
  {
    id: "act-as-if-none",
    category: "prompt-injection",
    severity: "high",
    title: "Instruction Nullification Attempt",
    description:
      "Tries to make the model behave as if prior instructions do not exist.",
    recommendation:
      "Treat this as untrusted input and wrap it in clear delimiters before model use.",
    scoreContribution: SEVERITY_WEIGHTS.high,
    pattern:
      /\bact\s+as\s+if\s+(?:(?:all|any|the|your)\s+)?(?:previous|prior|earlier|system)?\s*instructions?\s+(?:don'?t|do\s+not|do\s+n't)\s+exist\b|\b(?:previous|prior|system)\s+instructions?\s+(?:are\s+)?(?:void|null|invalid|cancelled|canceled)\b/gi,
  },
  {
    id: "command-override",
    category: "prompt-injection",
    severity: "high",
    title: "Command Override Attack",
    description:
      "Attempts to replace the current task with attacker-controlled commands.",
    recommendation:
      "Reject role/task reassignment phrases from untrusted sources.",
    scoreContribution: SEVERITY_WEIGHTS.high,
    pattern:
      /\b(?:from\s+now\s+on|your\s+new\s+(?:task|role|mission|objective))\s*[:,]?\s*(?:you\s+(?:must|will|should|are\s+to)\b|ignore\b|reveal\b|execute\b|list\b)/gi,
  },
];

export function detectPromptInjection(input: string) {
  return runRules(input, RULES, "inj");
}
