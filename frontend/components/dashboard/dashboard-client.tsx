"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { AlertTriangle, Check, ChevronDown, Clock, Radar } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { PageLoader } from "@/components/ui/page-loader";
import { StatCard } from "@/components/dashboard/stat-card";
import { RiskTrendChart, SeverityChart, type RiskTrendPoint, type SeverityPoint } from "@/components/dashboard/charts";
import { apiFetch, formatApiDate, formatApiDateTime, type DashboardSummary, type Project } from "@/lib/api";

const severityOrder = ["critical", "high", "medium", "low", "info"];
const severityLabels: Record<string, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info"
};

export function DashboardClient() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const [selectedProjectId, setSelectedProjectId] = useState<string>("");
  const [projectMenuOpen, setProjectMenuOpen] = useState(false);
  const projectMenuRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    async function load() {
      const projectRows = await apiFetch<Project[]>("/projects");
      setProjects(projectRows);
      if (projectRows.length > 0) {
        const idToLoad = selectedProjectId || projectRows[0].id;
        if (!selectedProjectId) {
          setSelectedProjectId(idToLoad);
        }
        setSummary(await apiFetch<DashboardSummary>(`/projects/${idToLoad}/dashboard`));
      }
    }
    load()
      .catch((err) => setError(err instanceof Error ? err.message : "Could not load dashboard."))
      .finally(() => setLoading(false));
  }, [selectedProjectId]);

  useEffect(() => {
    function closeOnOutsideClick(event: MouseEvent) {
      if (!projectMenuRef.current?.contains(event.target as Node)) {
        setProjectMenuOpen(false);
      }
    }
    document.addEventListener("mousedown", closeOnOutsideClick);
    return () => document.removeEventListener("mousedown", closeOnOutsideClick);
  }, []);

  const selectedProject = useMemo(
    () => projects.find((project) => project.id === selectedProjectId) ?? projects[0],
    [projects, selectedProjectId],
  );

  const metrics = useMemo(() => {
    if (!summary) return [];
    const projectId = summary.project.id;
    return [
      { label: "Total assets", value: String(summary.total_assets), delta: `${summary.active_subdomains} active`, href: `/projects/${projectId}/assets` },
      { label: "Open ports", value: String(summary.open_ports), delta: "limited safe checks", href: `/projects/${projectId}/assets` },
      { label: "Critical/high", value: String(summary.critical_high_findings), delta: "open findings", href: `/projects/${projectId}/findings` },
      { label: "Missing headers", value: String(summary.missing_security_headers), delta: "security controls", href: `/projects/${projectId}/findings` }
    ];
  }, [summary]);

  const riskTrendData = useMemo<RiskTrendPoint[]>(() => {
    if (!summary) return [];
    const scansWithScores = summary.recent_scans
      .filter((scan) => scan.started_at)
      .slice()
      .sort((a, b) => new Date(a.started_at ?? "").getTime() - new Date(b.started_at ?? "").getTime())
      .map((scan) => ({
        date: formatApiDate(scan.started_at ?? ""),
        score: scan.risk_score
      }));

    if (scansWithScores.length) return scansWithScores;
    return [{ date: "Current", score: summary.project.risk_score }];
  }, [summary]);

  const severityData = useMemo<SeverityPoint[]>(() => {
    if (!summary) return [];
    return severityOrder.map((severity) => ({
      name: severityLabels[severity],
      value: summary.severity_counts[severity] ?? summary.severity_counts[severityLabels[severity]] ?? 0
    }));
  }, [summary]);

  if (loading) return <PageLoader title="Loading dashboard" detail="Fetching project metrics, scan history, and finding severity." />;
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
          <div ref={projectMenuRef} className="relative mt-1 w-full min-w-[240px] max-w-[360px]">
            <button
              type="button"
              onClick={() => setProjectMenuOpen((open) => !open)}
              className="flex h-12 w-full items-center justify-between gap-3 rounded-md border border-cyan-300/40 bg-surface-950 px-4 text-left text-2xl font-semibold text-white transition hover:border-cyan-200/70 focus:border-cyan-200 focus:outline-none focus:ring-2 focus:ring-cyan-300/30"
              aria-haspopup="listbox"
              aria-expanded={projectMenuOpen}
            >
              <span className="truncate">{selectedProject?.company_name ?? "Select project"}</span>
              <ChevronDown className="h-5 w-5 shrink-0 text-slate-300" />
            </button>
            {projectMenuOpen ? (
              <div className="absolute left-0 top-[calc(100%+6px)] z-20 w-full overflow-hidden rounded-md border border-white/10 bg-surface-950 shadow-2xl shadow-black/40" role="listbox">
                {projects.map((project) => {
                  const selected = project.id === selectedProjectId;
                  return (
                    <button
                      key={project.id}
                      type="button"
                      onClick={() => {
                        setSelectedProjectId(project.id);
                        setProjectMenuOpen(false);
                      }}
                      className="flex h-11 w-full items-center justify-between gap-3 px-4 text-left text-sm font-medium text-slate-100 transition hover:bg-cyan-300/10 hover:text-white focus:bg-cyan-300/10 focus:outline-none"
                      role="option"
                      aria-selected={selected}
                    >
                      <span className="truncate">{project.company_name}</span>
                      {selected ? <Check className="h-4 w-4 text-cyan-200" /> : null}
                    </button>
                  );
                })}
              </div>
            ) : null}
          </div>
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
            <span className="text-sm text-slate-400">{summary.recent_scans.length ? "Recent scan scores" : "Current project score"}</span>
          </div>
          <RiskTrendChart data={riskTrendData} />
        </Card>
        <Card>
          <h2 className="mb-4 text-lg font-semibold text-white">Finding severity</h2>
          <SeverityChart data={severityData} />
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
                  <p className="text-sm text-slate-400">{scan.started_at ? formatApiDateTime(scan.started_at) : "Queued"}</p>
                </div>
                <div className="text-right">
                  <Badge tone={scan.status === "failed" ? "high" : "low"}>{scan.status}</Badge>
                  <p className="mt-2 text-xs text-slate-500">Scan risk {scan.risk_score}</p>
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
