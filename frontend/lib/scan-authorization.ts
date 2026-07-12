import { parseApiDate, type Project } from "./api";

type ScanScopeProject = Pick<Project, "authorization_expires_at" | "max_scan_profile">;

export function getAggressiveScanDisabledReason(project: ScanScopeProject, nowMs: number) {
  if (!project.authorization_expires_at) {
    return "Aggressive scanning is disabled because authorization expiry is missing.";
  }

  if (parseApiDate(project.authorization_expires_at).getTime() <= nowMs) {
    return "Aggressive scanning is disabled because authorization has expired.";
  }

  if (project.max_scan_profile !== "aggressive") {
    return "Aggressive scanning is disabled because this scope is approved for safe-only scanning.";
  }

  return null;
}
