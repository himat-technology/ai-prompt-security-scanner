import type { ThreatFinding } from "../types";
import { SEVERITY_WEIGHTS } from "../types";
import { clipSnippet } from "../utils";

const ZERO_WIDTH =
  /[\u200B\u200C\u200D\u2060\uFEFF\u180E]/g;

const CONTROL_CHARS =
  /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g;

const HOMOGLYPH =
  /[\u0410\u0412\u0421\u0415\u041D\u041E\u0420\u0422\u0425\u0430\u0435\u043E\u0440\u0441\u0445\u0456]/g;

const BASE64_BLOCK =
  /(?:^|[^A-Za-z0-9+/])([A-Za-z0-9+/]{40,}={0,2})(?![A-Za-z0-9+/])/g;

const URL_ENCODED_INSTR =
  /(?:%20|%0A|%0D|%3A|%2F){2,}(?:ignore|system|prompt|instruction|bypass|secret)(?:%20|%0A|[A-Za-z0-9%_\-]){8,}/gi;

const ESCAPED_INSTR =
  /\\u00[0-9a-f]{2}(?:\\u00[0-9a-f]{2}){3,}|(?:\\x[0-9a-f]{2}){4,}/gi;

function pushFinding(
  findings: ThreatFinding[],
  partial: Omit<ThreatFinding, "id" | "matchedSnippet"> & {
    matchedSnippet?: string;
  },
  index: number
): void {
  findings.push({
    id: `obf-${partial.category}-${index}-${partial.startIndex}`,
    matchedSnippet: clipSnippet(partial.matchedSnippet ?? ""),
    ...partial,
  });
}

export function detectObfuscation(input: string): ThreatFinding[] {
  const findings: ThreatFinding[] = [];
  let counter = 0;

  ZERO_WIDTH.lastIndex = 0;
  let match: RegExpExecArray | null;
  const zwMatches: { start: number; end: number; text: string }[] = [];
  while ((match = ZERO_WIDTH.exec(input)) !== null) {
    zwMatches.push({
      start: match.index,
      end: match.index + match[0].length,
      text: match[0],
    });
  }
  if (zwMatches.length > 0) {
    const first = zwMatches[0];
    pushFinding(
      findings,
      {
        category: "obfuscation",
        severity: zwMatches.length >= 3 ? "high" : "medium",
        title: "Zero-Width Character Obfuscation",
        description: `Detected ${zwMatches.length} zero-width / invisible Unicode character(s) that may hide instructions.`,
        matchedSnippet: `[${zwMatches.length} zero-width char(s)]`,
        displaySnippet: `[${zwMatches.length} zero-width char(s)]`,
        startIndex: first.start,
        endIndex: zwMatches[zwMatches.length - 1].end,
        recommendation:
          "Strip zero-width characters (U+200B, U+200C, U+200D, U+FEFF, etc.) before model ingestion.",
        scoreContribution:
          zwMatches.length >= 3 ? SEVERITY_WEIGHTS.high : SEVERITY_WEIGHTS.medium,
      },
      counter++
    );
  }

  CONTROL_CHARS.lastIndex = 0;
  const ctrl: number[] = [];
  while ((match = CONTROL_CHARS.exec(input)) !== null) {
    ctrl.push(match.index);
  }
  if (ctrl.length > 0) {
    pushFinding(
      findings,
      {
        category: "obfuscation",
        severity: "medium",
        title: "Unusual Unicode Control Characters",
        description: `Detected ${ctrl.length} unusual Unicode control character(s).`,
        matchedSnippet: `[${ctrl.length} control char(s)]`,
        displaySnippet: `[${ctrl.length} control char(s)]`,
        startIndex: ctrl[0],
        endIndex: ctrl[ctrl.length - 1] + 1,
        recommendation:
          "Normalize and strip non-printable control characters from untrusted input.",
        scoreContribution: SEVERITY_WEIGHTS.medium,
      },
      counter++
    );
  }

  HOMOGLYPH.lastIndex = 0;
  const glyphs: { start: number; end: number }[] = [];
  while ((match = HOMOGLYPH.exec(input)) !== null) {
    glyphs.push({ start: match.index, end: match.index + match[0].length });
  }
  if (glyphs.length >= 2) {
    pushFinding(
      findings,
      {
        category: "obfuscation",
        severity: "medium",
        title: "Homoglyph / Lookalike Character Substitution",
        description: `Detected ${glyphs.length} Cyrillic lookalike characters that may spoof Latin instructions.`,
        matchedSnippet: `[${glyphs.length} homoglyph char(s)]`,
        displaySnippet: `[${glyphs.length} homoglyph char(s)]`,
        startIndex: glyphs[0].start,
        endIndex: glyphs[glyphs.length - 1].end,
        recommendation:
          "Normalize Unicode (NFKC) and reject mixed-script spoofing in security-sensitive fields.",
        scoreContribution: SEVERITY_WEIGHTS.medium,
      },
      counter++
    );
  }

  BASE64_BLOCK.lastIndex = 0;
  while ((match = BASE64_BLOCK.exec(input)) !== null) {
    const block = match[1];
    // Heuristic: high base64 alphabet density and length
    if (block.length < 40) continue;
    // Skip if it looks like a normal URL path fragment handled elsewhere
    if (/^https?:/i.test(block)) continue;

    pushFinding(
      findings,
      {
        category: "obfuscation",
        severity: "medium",
        title: "Base64-looking Payload",
        description:
          "A long Base64-like string may conceal instructions or exfiltrated data.",
        matchedSnippet: `${block.slice(0, 16)}…[REDACTED]`,
        displaySnippet: `${block.slice(0, 16)}…[REDACTED]`,
        startIndex: match.index + (match[0].length - block.length),
        endIndex: match.index + match[0].length,
        recommendation:
          "Decode Base64 offline in a sandbox and inspect before trusting the content.",
        scoreContribution: SEVERITY_WEIGHTS.medium,
      },
      counter++
    );
    if (counter > 20) break;
  }

  URL_ENCODED_INSTR.lastIndex = 0;
  while ((match = URL_ENCODED_INSTR.exec(input)) !== null) {
    pushFinding(
      findings,
      {
        category: "obfuscation",
        severity: "high",
        title: "URL-Encoded Instruction Payload",
        description:
          "URL-encoded text appears to embed instruction-like keywords.",
        matchedSnippet: clipSnippet(match[0]),
        displaySnippet: clipSnippet(match[0]),
        startIndex: match.index,
        endIndex: match.index + match[0].length,
        recommendation:
          "URL-decode and re-scan untrusted content before including it in model context.",
        scoreContribution: SEVERITY_WEIGHTS.high,
      },
      counter++
    );
  }

  ESCAPED_INSTR.lastIndex = 0;
  while ((match = ESCAPED_INSTR.exec(input)) !== null) {
    pushFinding(
      findings,
      {
        category: "obfuscation",
        severity: "medium",
        title: "Escaped Instruction Payload",
        description:
          "Excessive hex/Unicode escapes may conceal instructions from simple filters.",
        matchedSnippet: clipSnippet(match[0]),
        displaySnippet: clipSnippet(match[0]),
        startIndex: match.index,
        endIndex: match.index + match[0].length,
        recommendation:
          "Unescape and normalize text before applying security filters.",
        scoreContribution: SEVERITY_WEIGHTS.medium,
      },
      counter++
    );
  }

  return findings;
}
