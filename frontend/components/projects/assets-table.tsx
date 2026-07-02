"use client";

import { useEffect, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import { assets as demoAssets } from "@/lib/demo-data";
import { apiFetch, type Asset } from "@/lib/api";

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
        firstSeen: new Date(asset.first_seen_at).toLocaleDateString(),
        lastSeen: new Date(asset.last_seen_at).toLocaleDateString()
      }))
    : projectId
      ? []
      : demoAssets;

  return (
    <Card>
      {loading ? <p className="mb-4 text-slate-400">Loading assets...</p> : null}
      {error ? <p className="mb-4 rounded-md border border-red-400/30 bg-red-500/10 p-3 text-sm text-red-100">{error}</p> : null}
      <div className="mb-4 grid gap-3 md:grid-cols-4">
        {["Search assets", "Status", "Risk level", "Technology"].map((label) => (
          <input key={label} className="h-10 rounded-md border border-white/10 bg-surface-950 px-3 text-sm outline-none focus:border-cyan-300/60" placeholder={label} />
        ))}
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
  );
}
