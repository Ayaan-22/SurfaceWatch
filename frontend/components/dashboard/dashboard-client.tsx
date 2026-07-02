"use client";

import { useEffect, useMemo, useState } from "react";
import { AlertTriangle, Clock, Radar } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { StatCard } from "@/components/dashboard/stat-card";
import { RiskTrendChart, SeverityChart } from "@/components/dashboard/charts";
import { apiFetch, type DashboardSummary, type Project } from "@/lib/api";

export function DashboardClient() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      const projectRows = await apiFetch<Project[]>("/projects");
      setProjects(projectRows);
      if (projectRows[0]) {
        setSummary(await apiFetch<DashboardSummary>(`/projects/${projectRows[0].id}/dashboard`));
      }
    }
    load()
      .catch((err) => setError(err instanceof Error ? err.message : "Could not load dashboard."))
      .finally(() => setLoading(false));
  }, []);

  const metrics = useMemo(() => {
    if (!summary) return [];
    return [
      { label: "Total assets", value: String(summary.total_assets), delta: `${summary.active_subdomains} active` },
      { label: "Open ports", value: String(summary.open_ports), delta: "limited safe checks" },
      { label: "Critical/high", value: String(summary.critical_high_findings), delta: "open findings" },
      { label: "Missing headers", value: String(summary.missing_security_headers), delta: "security controls" }
    ];
  }, [summary]);

  if (loading) return <Card><p className="text-slate-400">Loading dashboard...</p></Card>;
  if (error) return <Card><p className="text-red-100">{error}</p></Card>;
  if (!summary) {
    return (
      <Card className="text-center">
        <h1 className="text-2xl font-semibold text-white">No projects yet</h1>
        <p className="mt-2 text-slate-400">Create an authorized project to populate the dashboard.</p>
        <Button href="/projects/new" className="mt-5">Create project</Button>
      </Card>
    );
  }

  return (
    <>
      <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="text-sm text-slate-400">Dashboard</p>
          <h1 className="text-3xl font-semibold text-white">{summary.project.company_name}</h1>
        </div>
        <Badge tone={summary.project.risk_level}>{summary.project.risk_level} risk</Badge>
      </div>
      <div className="grid gap-5 md:grid-cols-2 xl:grid-cols-4">
        {metrics.map((metric) => <StatCard key={metric.label} {...metric} />)}
      </div>
      <div className="mt-5 grid gap-5 xl:grid-cols-[1.25fr_0.75fr]">
        <Card>
          <div className="mb-4 flex items-center justify-between">
            <h2 className="text-lg font-semibold text-white">Risk trend</h2>
            <span className="text-sm text-slate-400">Demo trend until more scans exist</span>
          </div>
          <RiskTrendChart />
        </Card>
        <Card>
          <h2 className="mb-4 text-lg font-semibold text-white">Finding severity</h2>
          <SeverityChart />
        </Card>
      </div>
      <div className="mt-5 grid gap-5 xl:grid-cols-2">
        <Card>
          <h2 className="mb-4 flex items-center gap-2 text-lg font-semibold text-white"><AlertTriangle size={18} /> Risky changes</h2>
          <div className="space-y-3">
            {summary.recent_changes.map((change) => (
              <div key={change.id} className="flex items-center justify-between rounded-lg border border-white/10 bg-surface-950 p-4">
                <div>
                  <p className="font-medium text-white">{change.change_type.replaceAll("_", " ")}</p>
                  <p className="text-sm text-slate-400">{change.new_value ?? change.old_value ?? "Change detected"}</p>
                </div>
                <Badge tone={change.severity}>{change.severity}</Badge>
              </div>
            ))}
            {!summary.recent_changes.length ? <p className="text-slate-400">No changes recorded yet.</p> : null}
          </div>
        </Card>
        <Card>
          <h2 className="mb-4 flex items-center gap-2 text-lg font-semibold text-white"><Clock size={18} /> Recent scans</h2>
          <div className="space-y-3">
            {summary.recent_scans.map((scan) => (
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
          </div>
        </Card>
      </div>
      <Card className="mt-5 border-emerald-400/20 bg-emerald-500/8">
        <div className="flex items-start gap-3">
          <Radar className="mt-1 text-emerald-200" size={20} />
          <p className="text-sm leading-6 text-emerald-100">Scans are intentionally conservative: passive-first discovery, limited ports, short timeouts, and no exploitation behavior.</p>
        </div>
      </Card>
    </>
  );
}
