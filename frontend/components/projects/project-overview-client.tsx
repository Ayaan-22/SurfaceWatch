"use client";

import { useEffect, useMemo, useState } from "react";
import { Play, RefreshCw } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { apiFetch, type Project, type Scan } from "@/lib/api";

export function ProjectOverviewClient({ projectId }: { projectId: string }) {
  const [project, setProject] = useState<Project | null>(null);
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function loadProject() {
    const [projectData, scanData] = await Promise.all([
      apiFetch<Project>(`/projects/${projectId}`),
      apiFetch<Scan[]>(`/projects/${projectId}/scans`)
    ]);
    setProject(projectData);
    setScans(scanData);
  }

  useEffect(() => {
    loadProject()
      .catch((err) => setError(err instanceof Error ? err.message : "Could not load project."))
      .finally(() => setLoading(false));
  }, [projectId]);

  async function startScan() {
    setError(null);
    setScanning(true);
    try {
      const scan = await apiFetch<Scan>(`/projects/${projectId}/scans`, { method: "POST" });
      setScans((current) => [scan, ...current]);
      window.setTimeout(() => {
        loadProject().catch(() => undefined);
      }, 2500);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not start scan.");
    } finally {
      setScanning(false);
    }
  }

  const latestScan = useMemo(() => scans[0], [scans]);

  if (loading) return <Card><p className="text-slate-400">Loading project...</p></Card>;
  if (error && !project) return <Card><p className="text-red-100">{error}</p><Button href="/login" className="mt-4" variant="secondary">Login</Button></Card>;
  if (!project) return null;

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="text-sm text-slate-400">Project overview</p>
          <h1 className="text-3xl font-semibold text-white">{project.company_name}</h1>
          <p className="mt-2 text-slate-400">{project.main_domain}</p>
        </div>
        <div className="flex flex-wrap gap-3">
          <Button href={`/projects/${project.id}/assets`} variant="secondary">Assets</Button>
          <Button href={`/projects/${project.id}/findings`} variant="secondary">Findings</Button>
          <button disabled={scanning} onClick={startScan} className="inline-flex h-10 items-center justify-center gap-2 rounded-md bg-cyan-300 px-4 text-sm font-semibold text-slate-950 transition hover:bg-cyan-200 disabled:cursor-not-allowed disabled:opacity-60">
            {scanning ? <RefreshCw className="animate-spin" size={17} /> : <Play size={17} />}
            {scanning ? "Queueing..." : "Run safe scan"}
          </button>
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
          <p className="mt-3 text-lg font-semibold text-white">{project.last_scan_at ? new Date(project.last_scan_at).toLocaleString() : "Not scanned"}</p>
        </Card>
        <Card>
          <p className="text-sm text-slate-400">Latest status</p>
          <p className="mt-3 text-lg font-semibold capitalize text-white">{latestScan?.status ?? "ready"}</p>
        </Card>
      </div>
      <Card>
        <div className="mb-4 flex items-center justify-between">
          <h2 className="text-lg font-semibold text-white">Recent scans</h2>
          <Button href={`/projects/${project.id}/scans`} variant="secondary">View all</Button>
        </div>
        <div className="space-y-3">
          {scans.slice(0, 4).map((scan) => (
            <div key={scan.id} className="flex items-center justify-between rounded-lg border border-white/10 bg-surface-950 p-4">
              <div>
                <p className="font-medium text-white">{scan.id}</p>
                <p className="text-sm text-slate-400">{scan.started_at ? new Date(scan.started_at).toLocaleString() : "Queued"}</p>
              </div>
              <div className="text-right">
                <Badge tone={scan.status === "failed" ? "high" : "low"}>{scan.status}</Badge>
                <p className="mt-2 text-xs text-slate-500">Risk {scan.risk_score}</p>
              </div>
            </div>
          ))}
          {!scans.length ? <p className="text-slate-400">No scans yet. Run a safe scan to populate assets and findings.</p> : null}
        </div>
      </Card>
    </div>
  );
}
