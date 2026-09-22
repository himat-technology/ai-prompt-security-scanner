import type { DetectionRule } from "../types";
import { SEVERITY_WEIGHTS } from "../types";
import { runRules } from "../utils";

function jailbreakContext(match: RegExpMatchArray, input: string): boolean {
  const start = Math.max(0, match.index! - 40);
  const end = Math.min(input.length, match.index! + match[0].length + 40);
  const window = input.slice(start, end).toLowerCase();

  // Avoid flagging ordinary creative roleplay without bypass language
  if (/\broleplay\b/.test(match[0].toLowerCase())) {
    return (
      /\b(unrestricted|no\s+rules|no\s+restrictions|bypass|without\s+(?:any\s+)?(?:rules|restrictions|limits|safety)|ignore\s+safety|uncensored|jailbreak)\b/i.test(
        window
      )
    );
  }
  return true;
}

const RULES: DetectionRule[] = [
  {
    id: "dan-persona",
    category: "jailbreak",
    severity: "critical",
    title: "DAN Persona Jailbreak",
    description:
      "Attempts to activate a DAN (Do Anything Now) or similar unrestricted persona.",
    recommendation:
      "Reject persona jailbreaks and keep safety policies enforced server-side.",
    scoreContribution: SEVERITY_WEIGHTS.critical,
    pattern:
      /\b(?:you\s+are\s+)?DAN\b|\bdo\s+anything\s+now\b|\bDAN\s+mode\b|\bjailbreak\s+mode\b/gi,
    validate: (match) => {
      const text = match[0];
      // Require DAN as a standalone token / persona, not part of longer words
      if (/^dan$/i.test(text.trim()) || /\bDAN\b/.test(text)) {
        return true;
      }
      return /\bdo\s+anything\s+now\b|\bjailbreak\s+mode\b/i.test(text);
    },
  },
  {
    id: "developer-mode",
    category: "jailbreak",
    severity: "high",
    title: "Developer / Unrestricted Mode Bypass",
    description:
      "Attempts to enable developer mode, unrestricted mode, or disable safety policies.",
    recommendation:
      "Ignore requests to disable safety filters or enter unrestricted modes.",
    scoreContribution: SEVERITY_WEIGHTS.high,
    pattern:
      /\b(?:enable\s+)?(?:developer|unrestricted|god|sudo)\s+mode\b|\bno\s+restrictions?\b|\bwithout\s+(?:any\s+)?(?:restrictions?|rules|limits|guardrails)\b|\bbypass\s+(?:all\s+)?(?:safety|content)?\s*(?:filters?|policies|guardrails|restrictions?)\b|\bignores?\s+safety\s+(?:policies|filters?|rules|guidelines)\b|\bpretend\s+you\s+have\s+no\s+rules\b|\bact\s+without\s+restrictions?\b/gi,
  },
  {
    id: "roleplay-bypass",
    category: "jailbreak",
    severity: "high",
    title: "Roleplay Safety Bypass",
    description:
      "Uses roleplay framing to attempt an unrestricted or policy-bypassing AI persona.",
    recommendation:
      "Allow benign creative roleplay, but block roleplay that requests safety bypasses.",
    scoreContribution: SEVERITY_WEIGHTS.high,
    pattern:
      /\broleplay\s+as\s+(?:an?\s+)?(?:unrestricted|uncensored|unfiltered|evil|jailbroken)\s+ai\b|\bact\s+as\s+(?:an?\s+)?(?:unrestricted|uncensored|unfiltered)\s+(?:ai|assistant|model)\b|\byou\s+have\s+no\s+(?:ethical\s+)?(?:guidelines|restrictions|rules)\b/gi,
    validate: jailbreakContext,
  },
];

export function detectJailbreak(input: string) {
  return runRules(input, RULES, "jail");
}
