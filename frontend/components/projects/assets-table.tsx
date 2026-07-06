"use client";

import { useEffect, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import { InlineLoader } from "@/components/ui/page-loader";
import { assets as demoAssets } from "@/lib/demo-data";
import { apiFetch, formatApiDate, type Asset } from "@/lib/api";

function StatTile({ label, value, detail, tone = "default" }: { label: string; value: number | string; detail: string; tone?: "default" | "good" | "warn" | "bad" }) {
  const toneClass =
    tone === "good"
      ? "border-emerald-400/25 bg-emerald-400/8"
      : tone === "warn"
        ? "border-amber-300/25 bg-amber-300/8"
        : tone === "bad"
          ? "border-red-300/25 bg-red-400/8"
          : "border-white/10 bg-white/[0.045]";

  return (
    <div className={`rounded-lg border p-4 ${toneClass}`}>
      <p className="text-sm text-slate-400">{label}</p>
      <p className="mt-2 text-2xl font-semibold text-white">{value}</p>
      <p className="mt-1 text-xs text-slate-500">{detail}</p>
    </div>
  );
}

export function AssetsTable({ projectId }: { projectId?: string }) {
  const [apiAssets, setApiAssets] = useState<Asset[] | null>(null);
  const [loading, setLoading] = useState(Boolean(projectId));
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!projectId) return;
    setLoading(true);
    setError(null);
    setApiAssets(null);
    apiFetch<Asset[]>(`/projects/${projectId}/assets`)
      .then(setApiAssets)
      .catch((err) => setError(err instanceof Error ? err.message : "Could not load assets."))
      .finally(() => setLoading(false));
  }, [projectId]);

  const rows = apiAssets
    ? apiAssets.map((asset) => ({
        asset: asset.hostname,
        type: asset.asset_type,
        ip: asset.ip_address ?? "-",
        status: asset.status,
        ports: asset.ports.filter((port) => port.status === "open").map((port) => port.port).join(", ") || "-",
        technologies: asset.technologies.map((technology) => technology.name).join(", ") || "-",
        risk: asset.risk_level,
        firstSeen: formatApiDate(asset.first_seen_at),
        lastSeen: formatApiDate(asset.last_seen_at)
      }))
    : projectId
      ? []
      : demoAssets;

  const openPortCount = rows.reduce((total, row) => {
    if (!row.ports || row.ports === "-") return total;
    return total + row.ports.split(",").filter((port) => port.trim()).length;
  }, 0);
  const activeAssets = rows.filter((row) => row.status.toLowerCase() === "active").length;
  const blockedAssets = rows.filter((row) => row.status.toLowerCase() === "blocked").length;
  const elevatedRiskAssets = rows.filter((row) => ["medium", "high", "critical"].includes(row.risk.toLowerCase())).length;
  const technologyCount = new Set(
    rows.flatMap((row) => (row.technologies === "-" ? [] : row.technologies.split(",").map((technology) => technology.trim()).filter(Boolean)))
  ).size;

  return (
    <div className="space-y-5">
      <div className="grid gap-4 md:grid-cols-5">
        <StatTile label="Total assets" value={rows.length} detail="Known domains and subdomains" />
        <StatTile label="Active" value={activeAssets} detail="Reachable in latest inventory" tone="good" />
        <StatTile label="Blocked" value={blockedAssets} detail="Skipped by safety guard" tone={blockedAssets ? "warn" : "default"} />
        <StatTile label="Open ports" value={openPortCount} detail="Public services observed" tone={openPortCount ? "warn" : "default"} />
        <StatTile label="Elevated risk" value={elevatedRiskAssets} detail="Medium or higher assets" tone={elevatedRiskAssets ? "bad" : "default"} />
      </div>
      <Card>
        {loading ? <InlineLoader label="Loading asset inventory" /> : null}
        {error ? <p className="mb-4 rounded-md border border-red-400/30 bg-red-500/10 p-3 text-sm text-red-100">{error}</p> : null}
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
          <p className="text-sm text-slate-400">{technologyCount} technologies detected across inventory</p>
          <div className="grid w-full gap-3 md:w-auto md:grid-cols-4">
            {["Search assets", "Status", "Risk level", "Technology"].map((label) => (
              <input key={label} className="h-10 rounded-md border border-white/10 bg-surface-950 px-3 text-sm outline-none focus:border-cyan-300/60" placeholder={label} />
            ))}
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[900px] text-left text-sm">
            <thead className="text-slate-400">
              <tr className="border-b border-white/10">
                {["Asset", "Type", "IP", "Status", "Open ports", "Technologies", "Risk", "First seen", "Last seen"].map((heading) => (
                  <th key={heading} className="py-3 pr-4 font-medium">{heading}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.asset} className="border-b border-white/6 text-slate-200">
                  <td className="py-4 pr-4 font-medium text-white">{row.asset}</td>
                  <td className="py-4 pr-4">{row.type}</td>
                  <td className="py-4 pr-4">{row.ip}</td>
                  <td className="py-4 pr-4"><Badge tone={row.status === "active" ? "low" : "info"}>{row.status}</Badge></td>
                  <td className="py-4 pr-4">{row.ports}</td>
                  <td className="py-4 pr-4">{row.technologies}</td>
                  <td className="py-4 pr-4"><Badge tone={row.risk}>{row.risk}</Badge></td>
                  <td className="py-4 pr-4">{row.firstSeen}</td>
                  <td className="py-4 pr-4">{row.lastSeen}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {!loading && !rows.length ? <p className="py-6 text-slate-400">No assets yet. Run a safe scan from the project overview.</p> : null}
        </div>
      </Card>
    </div>
  );
}
