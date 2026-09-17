import type { Severity, Verdict } from "../types";

const SEVERITY_ORDER: Severity[] = ["info", "low", "medium", "high", "critical"];

const severityRank = (severity: Severity): number => SEVERITY_ORDER.indexOf(severity);

export const meetsThreshold = (severity: Severity, threshold: Severity): boolean =>
  severityRank(severity) >= severityRank(threshold);

export const moreSevere = (current: Severity | undefined, candidate: Severity): Severity =>
  current === undefined || severityRank(candidate) > severityRank(current) ? candidate : current;

export const computeVerdict = (worst: Severity | undefined): Verdict => {
  if (worst === undefined) return "clean";
  if (meetsThreshold(worst, "high")) return "malicious";
  return "suspicious";
};
