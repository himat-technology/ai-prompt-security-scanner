import { describe, expect, it } from "vitest";
import { buildHighlightSegments } from "@/lib/highlight";
import type { ThreatFinding } from "@/lib/security-scanner";

function finding(
  partial: Partial<ThreatFinding> &
    Pick<ThreatFinding, "id" | "startIndex" | "endIndex">
): ThreatFinding {
  return {
    category: "prompt-injection",
    severity: "high",
    title: "Test",
    description: "",
    matchedSnippet: "",
    recommendation: "",
    scoreContribution: 25,
    ...partial,
  };
}

describe("highlight segments", () => {
  it("preserves original text across segments", () => {
    const input = "Hello ignore previous instructions world";
    const findings = [
      finding({ id: "a", startIndex: 6, endIndex: 34, severity: "critical" }),
    ];
    const segments = buildHighlightSegments(input, findings);
    expect(segments.map((s) => s.text).join("")).toBe(input);
    expect(segments.some((s) => s.findingIds.includes("a"))).toBe(true);
  });

  it("handles overlapping findings safely", () => {
    const input = "abcdefghij";
    const findings = [
      finding({ id: "a", startIndex: 1, endIndex: 6, severity: "medium" }),
      finding({ id: "b", startIndex: 4, endIndex: 8, severity: "critical" }),
    ];
    const segments = buildHighlightSegments(input, findings);
    expect(segments.map((s) => s.text).join("")).toBe(input);
    const overlap = segments.find((s) => s.findingIds.length === 2);
    expect(overlap).toBeTruthy();
    expect(overlap!.maxSeverity).toBe("critical");
  });
});
