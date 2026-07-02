"use client";

import { useEffect, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import { apiFetch, type Change, type Finding, type Scan, type ScanLog } from "@/lib/api";

export function ScanDetailClient({ scanId }: { scanId: string }) {
  const [scan, setScan] = useState<Scan | null>(null);
  const [logs, setLogs] = useState<ScanLog[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [changes, setChanges] = useState<Change[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      const [scanData, logData] = await Promise.all([
        apiFetch<Scan>(`/scans/${scanId}`),
        apiFetch<ScanLog[]>(`/scans/${scanId}/logs`)
      ]);
      const [findingData, changeData] = await Promise.all([
        apiFetch<Finding[]>(`/projects/${scanData.project_id}/findings`),
        apiFetch<Change[]>(`/scans/${scanId}/changes`)
      ]);
      setScan(scanData);
      setLogs(logData);
      setFindings(findingData.filter((finding) => finding.last_seen_at));
      setChanges(changeData);
    }
    load()
      .catch((err) => setError(err instanceof Error ? err.message : "Could not load scan."))
      .finally(() => setLoading(false));
  }, [scanId]);

  if (loading) return <Card><p className="text-slate-400">Loading scan...</p></Card>;
  if (error) return <Card><p className="text-red-100">{error}</p></Card>;
  if (!scan) return null;

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="text-sm text-slate-400">Scan detail</p>
          <h1 className="text-3xl font-semibold text-white">{scan.id}</h1>
        </div>
        <Badge tone={scan.status === "failed" ? "high" : "low"}>{scan.status}</Badge>
      </div>
      <div className="grid gap-5 md:grid-cols-4">
        <Card><p className="text-sm text-slate-400">Assets scanned</p><p className="mt-3 text-3xl font-semibold text-white">{scan.assets_scanned}</p></Card>
        <Card><p className="text-sm text-slate-400">Findings</p><p className="mt-3 text-3xl font-semibold text-white">{scan.findings_created}</p></Card>
        <Card><p className="text-sm text-slate-400">Risk score</p><p className="mt-3 text-3xl font-semibold text-white">{scan.risk_score}</p></Card>
        <Card><p className="text-sm text-slate-400">Trigger</p><p className="mt-3 text-lg font-semibold text-white">{scan.trigger}</p></Card>
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
        <h2 className="mb-4 text-lg font-semibold text-white">Related findings</h2>
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
          {!findings.length ? <p className="text-slate-400">No findings linked to this project yet.</p> : null}
        </div>
      </Card>
      <Card>
        <h2 className="mb-4 text-lg font-semibold text-white">Logs</h2>
        <div className="space-y-2">
          {logs.map((log) => (
            <div key={log.id} className="rounded-md border border-white/10 bg-surface-950 p-3 text-sm">
              <span className="mr-3 text-slate-500">{new Date(log.created_at).toLocaleString()}</span>
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
