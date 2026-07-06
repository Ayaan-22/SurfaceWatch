"use client";

import { useEffect, useRef, useState } from "react";
import { RefreshCw, StopCircle } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import { PageLoader } from "@/components/ui/page-loader";
import { apiDateMs, apiFetch, formatApiDateTime, type Asset, type Change, type Finding, type Project, type Scan, type ScanLog } from "@/lib/api";

function formatElapsed(ms: number) {
  const totalSeconds = Math.max(0, Math.floor(ms / 1000));
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  if (minutes >= 60) {
    const hours = Math.floor(minutes / 60);
    const remainingMinutes = minutes % 60;
    return `${hours}h ${remainingMinutes}m ${seconds}s`;
  }
  return `${minutes}m ${seconds}s`;
}

function isActiveScan(status: string) {
  return status === "pending" || status === "queued" || status === "running";
}

export function ScanDetailClient({ scanId }: { scanId: string }) {
  const [scan, setScan] = useState<Scan | null>(null);
  const [project, setProject] = useState<Project | null>(null);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [logs, setLogs] = useState<ScanLog[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [changes, setChanges] = useState<Change[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [cancelling, setCancelling] = useState(false);
  const [nowMs, setNowMs] = useState(() => Date.now());

  const scanRef = useRef<Scan | null>(null);

  useEffect(() => {
    scanRef.current = scan;
  }, [scan]);

  useEffect(() => {
    let active = true;
    async function load() {
      try {
        const scanData = await apiFetch<Scan>(`/scans/${scanId}`);
        const logData = await apiFetch<ScanLog[]>(`/scans/${scanId}/logs`);
        const [projectData, assetData, findingData, changeData] = await Promise.all([
          apiFetch<Project>(`/projects/${scanData.project_id}`),
          apiFetch<Asset[]>(`/projects/${scanData.project_id}/assets`),
          apiFetch<Finding[]>(`/projects/${scanData.project_id}/findings`),
          apiFetch<Change[]>(`/scans/${scanId}/changes`)
        ]);
        if (active) {
          setScan(scanData);
          setProject(projectData);
          setAssets(assetData);
          setLogs(logData);
          setFindings(findingData.filter((finding) => finding.status === "open"));
          setChanges(changeData);
          setError(null);
        }
      } catch (err) {
        if (active) {
          setError(err instanceof Error ? err.message : "Could not load scan.");
        }
      } finally {
        if (active) {
          setLoading(false);
        }
      }
    }

    load();

    const intervalId = setInterval(() => {
      const currentScan = scanRef.current;
      const isRunning = currentScan ? isActiveScan(currentScan.status) : true;
      if (!isRunning) return;
      load();
    }, 3000);

    return () => {
      active = false;
      clearInterval(intervalId);
    };
  }, [scanId]);

  useEffect(() => {
    if (!scan || !isActiveScan(scan.status)) return;
    setNowMs(Date.now());
    const intervalId = setInterval(() => setNowMs(Date.now()), 1000);
    return () => clearInterval(intervalId);
  }, [scan]);

  async function cancelScan() {
    setError(null);
    setCancelling(true);
    try {
      const cancelledScan = await apiFetch<Scan>(`/scans/${scanId}/cancel`, { method: "POST" });
      setScan(cancelledScan);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not cancel scan.");
    } finally {
      setCancelling(false);
    }
  }

  if (loading) return <PageLoader title="Loading scan" detail="Gathering logs, assets, changes, and current findings." />;
  if (error && !scan) return <Card><p className="text-red-100">{error}</p></Card>;
  if (!scan) return null;

  const activeScan = isActiveScan(scan.status);
  const elapsedStart = scan.started_at ?? scan.created_at;
  const elapsedMs = activeScan ? nowMs - apiDateMs(elapsedStart) : 0;
  const currentRiskScore = project?.risk_score ?? scan.risk_score;
  const currentRiskLevel = project?.risk_level ?? "low";

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="text-sm text-slate-400">Scan detail</p>
          <h1 className="text-3xl font-semibold text-white">{scan.id}</h1>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          {activeScan ? (
            <div className="inline-flex h-10 items-center gap-2 rounded-md border border-cyan-300/30 bg-cyan-300/10 px-3 text-sm font-medium text-cyan-100">
              <span className="h-2 w-2 rounded-full bg-cyan-300 animate-pulse" />
              <RefreshCw className="h-4 w-4 animate-spin" />
              <span>Scanning in progress</span>
              <span className="text-slate-300">Elapsed: {formatElapsed(elapsedMs)}</span>
            </div>
          ) : null}
          {activeScan ? (
            <button
              disabled={cancelling}
              onClick={cancelScan}
              className="inline-flex h-10 items-center justify-center gap-2 rounded-md border border-red-400/40 bg-red-500/14 px-4 text-sm font-semibold text-red-100 transition hover:bg-red-500/20 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {cancelling ? <RefreshCw className="h-4 w-4 animate-spin" /> : <StopCircle className="h-4 w-4" />}
              {cancelling ? "Cancelling..." : "Cancel scan"}
            </button>
          ) : null}
          <Badge tone={scan.status === "failed" ? "high" : activeScan ? "info" : "low"}>{scan.status}</Badge>
        </div>
      </div>
      {error ? <p className="rounded-md border border-red-400/30 bg-red-500/10 p-3 text-sm text-red-100">{error}</p> : null}
      <div className="grid gap-5 md:grid-cols-3 xl:grid-cols-5">
        <Card><p className="text-sm text-slate-400">Assets this scan</p><p className="mt-3 text-3xl font-semibold text-white">{scan.assets_scanned}</p></Card>
        <Card><p className="text-sm text-slate-400">Total assets</p><p className="mt-3 text-3xl font-semibold text-white">{assets.length}</p></Card>
        <Card><p className="text-sm text-slate-400">Open findings</p><p className="mt-3 text-3xl font-semibold text-white">{findings.length}</p></Card>
        <Card>
          <p className="text-sm text-slate-400">Current risk score</p>
          <div className="mt-3 flex items-center gap-3">
            <p className="text-3xl font-semibold text-white">{currentRiskScore}</p>
            <Badge tone={currentRiskLevel}>{currentRiskLevel}</Badge>
          </div>
        </Card>
        <Card><p className="text-sm text-slate-400">Profile</p><p className="mt-3 text-lg font-semibold capitalize text-white">{scan.scan_profile}</p></Card>
      </div>
      <Card>
        <h2 className="mb-4 text-lg font-semibold text-white">Changes from this scan</h2>
        <div className="space-y-2">
          {changes.map((change) => (
            <div key={change.id} className="flex items-center justify-between rounded-md border border-white/10 bg-surface-950 p-3 text-sm">
              <div>
                <p className="font-medium text-white">{change.change_type.replaceAll("_", " ")}</p>
                <p className="text-slate-400">{change.old_value ?? "-"} {"->"} {change.new_value ?? "-"}</p>
              </div>
              <Badge tone={change.severity}>{change.severity}</Badge>
            </div>
          ))}
          {!changes.length ? <p className="text-slate-400">No changes recorded for this scan.</p> : null}
        </div>
      </Card>
      <Card>
        <h2 className="mb-4 text-lg font-semibold text-white">Current project findings</h2>
        <div className="space-y-2">
          {findings.slice(0, 10).map((finding) => (
            <div key={finding.id} className="flex items-center justify-between rounded-md border border-white/10 bg-surface-950 p-3 text-sm">
              <div>
                <p className="font-medium text-white">{finding.title}</p>
                <p className="text-slate-400">{finding.category}</p>
              </div>
              <Badge tone={finding.severity}>{finding.severity}</Badge>
            </div>
          ))}
          {!findings.length ? <p className="text-slate-400">No open findings linked to this project.</p> : null}
        </div>
      </Card>
      <Card>
        <h2 className="mb-4 text-lg font-semibold text-white">Logs</h2>
        <div className="space-y-2">
          {logs.map((log) => (
            <div key={log.id} className="rounded-md border border-white/10 bg-surface-950 p-3 text-sm">
              <span className="mr-3 text-slate-500">{formatApiDateTime(log.created_at)}</span>
              <span className={log.level === "error" ? "text-red-200" : "text-cyan-100"}>{log.level}</span>
              <span className="ml-3 text-slate-300">{log.message}</span>
            </div>
          ))}
          {!logs.length ? <p className="text-slate-400">No logs recorded yet.</p> : null}
        </div>
      </Card>
    </div>
  );
}
