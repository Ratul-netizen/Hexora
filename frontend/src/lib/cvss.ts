/**
 * CVSS v3.1 base score.
 *
 * A finding is not bug-bounty-ready without a severity a triager can check, and "high"
 * on its own is an opinion. The vector string is the receipt: it says exactly which
 * assumptions produced the number, so a reviewer can disagree with the input rather than
 * the verdict. This computes the base metrics only — the part that travels with a report.
 *
 * Formula and constants are the FIRST CVSS v3.1 specification.
 */

export type MetricKey = "AV" | "AC" | "PR" | "UI" | "S" | "C" | "I" | "A";

export interface MetricDef {
  key: MetricKey;
  label: string;
  options: { value: string; label: string }[];
}

export const METRICS: MetricDef[] = [
  {
    key: "AV",
    label: "Attack Vector",
    options: [
      { value: "N", label: "Network" },
      { value: "A", label: "Adjacent" },
      { value: "L", label: "Local" },
      { value: "P", label: "Physical" },
    ],
  },
  {
    key: "AC",
    label: "Attack Complexity",
    options: [
      { value: "L", label: "Low" },
      { value: "H", label: "High" },
    ],
  },
  {
    key: "PR",
    label: "Privileges Required",
    options: [
      { value: "N", label: "None" },
      { value: "L", label: "Low" },
      { value: "H", label: "High" },
    ],
  },
  {
    key: "UI",
    label: "User Interaction",
    options: [
      { value: "N", label: "None" },
      { value: "R", label: "Required" },
    ],
  },
  {
    key: "S",
    label: "Scope",
    options: [
      { value: "U", label: "Unchanged" },
      { value: "C", label: "Changed" },
    ],
  },
  {
    key: "C",
    label: "Confidentiality",
    options: [
      { value: "N", label: "None" },
      { value: "L", label: "Low" },
      { value: "H", label: "High" },
    ],
  },
  {
    key: "I",
    label: "Integrity",
    options: [
      { value: "N", label: "None" },
      { value: "L", label: "Low" },
      { value: "H", label: "High" },
    ],
  },
  {
    key: "A",
    label: "Availability",
    options: [
      { value: "N", label: "None" },
      { value: "L", label: "Low" },
      { value: "H", label: "High" },
    ],
  },
];

export type Metrics = Record<MetricKey, string>;

export const DEFAULT_METRICS: Metrics = {
  AV: "N",
  AC: "L",
  PR: "N",
  UI: "N",
  S: "U",
  C: "H",
  I: "H",
  A: "H",
};

const AV: Record<string, number> = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
const AC: Record<string, number> = { L: 0.77, H: 0.44 };
const UI: Record<string, number> = { N: 0.85, R: 0.62 };
const CIA: Record<string, number> = { N: 0, L: 0.22, H: 0.56 };
// Privileges Required depends on whether Scope changed.
const PR_UNCHANGED: Record<string, number> = { N: 0.85, L: 0.62, H: 0.27 };
const PR_CHANGED: Record<string, number> = { N: 0.85, L: 0.68, H: 0.5 };

/** CVSS's specific round-half-up-to-one-decimal. */
function roundup(input: number): number {
  const i = Math.round(input * 100000);
  if (i % 10000 === 0) return i / 100000;
  return (Math.floor(i / 10000) + 1) / 10;
}

export function severityOf(score: number): string {
  if (score === 0) return "None";
  if (score < 4) return "Low";
  if (score < 7) return "Medium";
  if (score < 9) return "High";
  return "Critical";
}

export interface CvssResult {
  score: number;
  severity: string;
  vector: string;
}

export function computeBase(m: Metrics): CvssResult {
  const scopeChanged = m.S === "C";
  const iss = 1 - (1 - CIA[m.C]!) * (1 - CIA[m.I]!) * (1 - CIA[m.A]!);
  const impact = scopeChanged
    ? 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15)
    : 6.42 * iss;
  const pr = (scopeChanged ? PR_CHANGED : PR_UNCHANGED)[m.PR]!;
  const exploitability = 8.22 * AV[m.AV]! * AC[m.AC]! * pr * UI[m.UI]!;

  let score: number;
  if (impact <= 0) score = 0;
  else if (scopeChanged) score = roundup(Math.min(1.08 * (impact + exploitability), 10));
  else score = roundup(Math.min(impact + exploitability, 10));

  const vector =
    "CVSS:3.1/" + METRICS.map((d) => `${d.key}:${m[d.key]}`).join("/");
  return { score, severity: severityOf(score), vector };
}
