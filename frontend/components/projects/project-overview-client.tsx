"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Play, RefreshCw, ShieldAlert } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { PageLoader } from "@/components/ui/page-loader";
import Link from "next/link";
import { apiFetch, formatApiDate, formatApiDateTime, parseApiDate, type Project, type Scan } from "@/lib/api";
import { getAggressiveScanDisabledReason } from "@/lib/scan-authorization";

export function ProjectOverviewClient({ projectId }: { projectId: string }) {
  const [project, setProject] = useState<Project | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState<"safe" | "aggressive" | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [nowMs, setNowMs] = useState(0);

  const scansRef = useRef<Scan[]>([]);

  useEffect(() => {
    scansRef.current = scans;
  }, [scans]);

  const loadProject = useCallback(async () => {
    const [projectData, scanData] = await Promise.all([
      apiFetch<Project>(`/projects/${projectId}`),
      apiFetch<Scan[]>(`/projects/${projectId}/scans`)
    ]);
    setProject(projectData);
    setScans(scanData);
  }, [projectId]);

  useEffect(() => {
    let active = true;
    async function load() {
      try {
        setNowMs(Date.now());
        await loadProject();
        if (active) setError(null);
      } catch (err) {
        if (active) setError(err instanceof Error ? err.message : "Could not load project.");
      } finally {
        if (active) setLoading(false);
      }
    }

    load();

    const intervalId = setInterval(() => {
      const currentScans = scansRef.current;
      const anyRunning = currentScans.some((s) => ["queued", "pending", "claimed", "running"].includes(s.status));
      if (!anyRunning && currentScans.length > 0) return;
      load();
    }, 3000);

    return () => {
      active = false;
      clearInterval(intervalId);
    };
  }, [loadProject]);

  async function startScan(scanProfile: "safe" | "aggressive") {
    setError(null);
    setScanning(scanProfile);
    try {
      const scan = await apiFetch<Scan>(`/projects/${projectId}/scans`, {
        method: "POST",
        body: JSON.stringify({ scan_profile: scanProfile })
      });
      setScans((current) => [scan, ...current]);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not start scan.");
    } finally {
      setScanning(null);
    }
  }

  const latestScan = useMemo(() => scans[0], [scans]);

  if (loading) return <PageLoader title="Loading project" detail="Preparing scope details, authorization, and recent scans." />;
  if (error && !project) return <Card><p className="text-red-100">{error}</p><Button href="/login" className="mt-4" variant="secondary">Login</Button></Card>;
  if (!project) return null;

  const authorizationExpired = project.authorization_expires_at ? parseApiDate(project.authorization_expires_at).getTime() <= nowMs : true;
  const authorizationDisabledReason = !project.authorization_expires_at
    ? "Authorization expiry is missing."
    : authorizationExpired
      ? `Authorization expired on ${formatApiDate(project.authorization_expires_at)}.`
      : null;
  const aggressiveDisabledReason = getAggressiveScanDisabledReason(project, nowMs);
  const canRunAggressive = aggressiveDisabledReason === null;
  const canRunSafe = !authorizationExpired;
  const scopeSettingsHref = `/projects/${project.id}/settings`;

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="text-sm text-slate-400">Project overview</p>
          <h1 className="text-3xl font-semibold text-white">{project.company_name}</h1>
          <p className="mt-2 text-slate-400">{project.main_domain}</p>
        </div>
        <div className="flex max-w-xl flex-col items-start gap-3 sm:items-end">
          <div className="flex flex-wrap justify-start gap-3 sm:justify-end">
            <Button href={`/projects/${project.id}/assets`} variant="secondary">Assets</Button>
            <Button href={`/projects/${project.id}/findings`} variant="secondary">Findings</Button>
            <button disabled={scanning !== null || !canRunSafe} onClick={() => startScan("safe")} className="inline-flex h-10 items-center justify-center gap-2 rounded-md bg-cyan-300 px-4 text-sm font-semibold text-slate-950 transition hover:bg-cyan-200 disabled:cursor-not-allowed disabled:opacity-60">
              {scanning === "safe" ? <RefreshCw className="animate-spin" size={17} /> : <Play size={17} />}
              {scanning === "safe" ? "Queueing..." : "Run safe scan"}
            </button>
            <button
              aria-describedby={aggressiveDisabledReason ? "aggressive-scan-disabled-reason" : undefined}
              disabled={scanning !== null || !canRunAggressive}
              onClick={() => startScan("aggressive")}
              title={aggressiveDisabledReason ?? undefined}
              className="inline-flex h-10 items-center justify-center gap-2 rounded-md border border-red-300/50 bg-red-500/15 px-4 text-sm font-semibold text-red-100 transition hover:bg-red-500/25 disabled:cursor-not-allowed disabled:opacity-70"
            >
              {scanning === "aggressive" ? <RefreshCw className="animate-spin" size={17} /> : <ShieldAlert size={17} />}
              {scanning === "aggressive" ? "Queueing..." : "Run aggressive scan"}
            </button>
          </div>
          {aggressiveDisabledReason ? (
            <div id="aggressive-scan-disabled-reason" className="flex w-full flex-col gap-3 rounded-md border border-amber-300/30 bg-amber-400/10 p-3 text-sm text-amber-100 sm:flex-row sm:items-center sm:justify-between">
              <p>{aggressiveDisabledReason}</p>
              <Button href={scopeSettingsHref} variant="secondary" className="shrink-0">Update project scope</Button>
            </div>
          ) : null}
        </div>
      </div>
      {error ? <p className="rounded-md border border-red-400/30 bg-red-500/10 p-3 text-sm text-red-100">{error}</p> : null}
      <div className="grid gap-5 md:grid-cols-4">
        <Card>
          <p className="text-sm text-slate-400">Risk score</p>
          <p className="mt-3 text-3xl font-semibold text-white">{project.risk_score}</p>
        </Card>
        <Card>
          <p className="text-sm text-slate-400">Risk level</p>
          <div className="mt-4"><Badge tone={project.risk_level}>{project.risk_level}</Badge></div>
        </Card>
        <Card>
          <p className="text-sm text-slate-400">Last scan</p>
          <p className="mt-3 text-lg font-semibold text-white">{project.last_scan_at ? formatApiDateTime(project.last_scan_at) : "Not scanned"}</p>
        </Card>
        <Card>
          <p className="text-sm text-slate-400">Latest status</p>
          <p className="mt-3 text-lg font-semibold capitalize text-white">{latestScan?.status ?? "ready"}</p>
        </Card>
      </div>
      <Card>
        <div className="grid gap-4 md:grid-cols-3">
          <div>
            <p className="text-sm text-slate-400">Authorization contact</p>
            <p className="mt-2 font-medium text-white">{project.authorization_contact ?? "Not recorded"}</p>
          </div>
          <div>
            <p className="text-sm text-slate-400">Authorization expiry</p>
            <p className="mt-2 font-medium text-white">{project.authorization_expires_at ? formatApiDate(project.authorization_expires_at) : "Missing"}</p>
          </div>
          <div>
            <p className="text-sm text-slate-400">Approved scan profile</p>
            <p className="mt-2 font-medium capitalize text-white">{project.max_scan_profile}</p>
          </div>
        </div>
        {authorizationDisabledReason ? (
          <div className="mt-4 flex flex-col gap-3 rounded-md border border-amber-300/30 bg-amber-400/10 p-3 text-sm text-amber-100 sm:flex-row sm:items-center sm:justify-between">
            <p>{authorizationDisabledReason} Update the project scope before starting new scans.</p>
            <Button href={scopeSettingsHref} variant="secondary" className="shrink-0">Update project scope</Button>
          </div>
        ) : null}
      </Card>
      <Card>
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">Recent scans</h2>
          <Button href={`/projects/${project.id}/scans`} variant="secondary">View all</Button>
        </div>
        <div className="space-y-3">
          {scans.slice(0, 4).map((scan) => (
            <div key={scan.id} className="flex items-center justify-between rounded-lg border border-white/10 bg-surface-950 p-4">
              <div>
                <p className="font-medium text-white">
                  <Link href={`/scans/${scan.id}`} className="text-cyan-100 hover:text-cyan-200">
                    {scan.id}
                  </Link>
                </p>
                <p className="text-sm text-slate-400">{scan.started_at ? formatApiDateTime(scan.started_at) : "Queued"} · {scan.scan_profile}</p>
              </div>
              <div className="text-right">
                <Badge tone={scan.status === "failed" ? "high" : scan.status === "partial" ? "medium" : ["queued", "pending", "claimed", "running"].includes(scan.status) ? "info" : "low"}>{scan.status}</Badge>
                <p className="mt-2 text-xs text-slate-500">Scan risk {scan.risk_score}</p>
              </div>
            </div>
          ))}
          {!scans.length ? <p className="text-slate-400">No scans yet. Run an approved scan to populate assets and findings.</p> : null}
        </div>
      </Card>
    </div>
  );
}
