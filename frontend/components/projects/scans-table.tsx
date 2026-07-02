"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import { apiFetch, type Scan } from "@/lib/api";
import { scans as demoScans } from "@/lib/demo-data";

export function ScansTable({ projectId }: { projectId?: string }) {
  const [apiScans, setApiScans] = useState<Scan[] | null>(null);
  const [loading, setLoading] = useState(Boolean(projectId));
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!projectId) return;
    apiFetch<Scan[]>(`/projects/${projectId}/scans`)
      .then(setApiScans)
      .catch((err) => setError(err instanceof Error ? err.message : "Could not load scans."))
      .finally(() => setLoading(false));
  }, [projectId]);

  const rows = apiScans
    ? apiScans.map((scan) => ({
        id: scan.id,
        status: scan.status,
        started: scan.started_at ? new Date(scan.started_at).toLocaleString() : "Queued",
        duration: scan.finished_at && scan.started_at ? `${Math.max(1, Math.round((Date.parse(scan.finished_at) - Date.parse(scan.started_at)) / 1000))}s` : "-",
        assets: scan.assets_scanned,
        findings: scan.findings_created,
        score: scan.risk_score
      }))
    : demoScans;

  return (
    <Card>
      {loading ? <p className="mb-4 text-slate-400">Loading scans...</p> : null}
      {error ? <p className="mb-4 rounded-md border border-red-400/30 bg-red-500/10 p-3 text-sm text-red-100">{error}</p> : null}
      <div className="overflow-x-auto">
        <table className="w-full min-w-[760px] text-left text-sm">
          <thead className="text-slate-400">
            <tr className="border-b border-white/10">
              {["Scan ID", "Start time", "Duration", "Status", "Assets", "Findings", "Risk score"].map((heading) => <th key={heading} className="py-3 pr-4 font-medium">{heading}</th>)}
            </tr>
          </thead>
          <tbody>
            {rows.map((scan) => (
              <tr key={scan.id} className="border-b border-white/6 text-slate-200">
                <td className="py-4 pr-4 font-medium text-white"><Link className="text-cyan-100 hover:text-cyan-200" href={`/scans/${scan.id}`}>{scan.id}</Link></td>
                <td className="py-4 pr-4">{scan.started}</td>
                <td className="py-4 pr-4">{scan.duration}</td>
                <td className="py-4 pr-4"><Badge tone={scan.status === "failed" ? "high" : "low"}>{scan.status}</Badge></td>
                <td className="py-4 pr-4">{scan.assets}</td>
                <td className="py-4 pr-4">{scan.findings}</td>
                <td className="py-4 pr-4">{scan.score}</td>
              </tr>
            ))}
          </tbody>
        </table>
        {!loading && !rows.length ? <p className="py-6 text-slate-400">No scans yet. Start one from the project overview.</p> : null}
      </div>
    </Card>
  );
}
