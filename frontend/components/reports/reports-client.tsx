"use client";

import { useEffect, useState } from "react";
import { Download, FileSpreadsheet, FileText } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { apiFetch, downloadReport, type Report } from "@/lib/api";

export function ReportsClient({ projectId }: { projectId: string }) {
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function loadReports() {
    setReports(await apiFetch<Report[]>(`/projects/${projectId}/reports`));
  }

  useEffect(() => {
    loadReports().catch((err) => setError(err instanceof Error ? err.message : "Could not load reports."));
  }, [projectId]);

  async function generate(type: "pdf" | "excel") {
    setError(null);
    setLoading(true);
    try {
      const report = await apiFetch<Report>(`/projects/${projectId}/reports/${type}`, { method: "POST" });
      await loadReports();
      if (report.status === "ready") {
        await downloadReport(report.id);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not generate report.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-5">
      {error ? <p className="rounded-md border border-red-400/30 bg-red-500/10 p-3 text-sm text-red-100">{error}</p> : null}
      <div className="grid gap-5 md:grid-cols-2">
        <Card>
          <FileText className="mb-5 text-cyan-200" size={28} />
          <h2 className="text-lg font-semibold text-white">PDF executive report</h2>
          <p className="mt-3 leading-7 text-slate-400">Cover page, score summary, findings, recommendations, and authorization disclaimer.</p>
          <button disabled={loading} onClick={() => generate("pdf")} className="mt-6 inline-flex h-10 items-center justify-center gap-2 rounded-md border border-white/12 bg-white/8 px-4 text-sm font-semibold text-slate-100 transition hover:bg-white/12 disabled:opacity-60">
            <Download size={17} /> Generate PDF
          </button>
        </Card>
        <Card>
          <FileSpreadsheet className="mb-5 text-emerald-200" size={28} />
          <h2 className="text-lg font-semibold text-white">Excel workbook</h2>
          <p className="mt-3 leading-7 text-slate-400">Summary, assets, findings, ports, headers, SSL/TLS, technologies, and scan metadata sheets.</p>
          <button disabled={loading} onClick={() => generate("excel")} className="mt-6 inline-flex h-10 items-center justify-center gap-2 rounded-md border border-white/12 bg-white/8 px-4 text-sm font-semibold text-slate-100 transition hover:bg-white/12 disabled:opacity-60">
            <Download size={17} /> Generate Excel
          </button>
        </Card>
      </div>
      <Card>
        <h2 className="mb-4 text-lg font-semibold text-white">Generated reports</h2>
        <div className="space-y-3">
          {reports.map((report) => (
            <div key={report.id} className="flex items-center justify-between rounded-lg border border-white/10 bg-surface-950 p-4">
              <div>
                <p className="font-medium text-white">{report.report_type.toUpperCase()} report</p>
                <p className="text-sm text-slate-400">{new Date(report.created_at).toLocaleString()} - {report.status}</p>
              </div>
              {report.status === "ready" ? (
                <button onClick={() => downloadReport(report.id)} className="rounded-md border border-white/12 bg-white/8 px-3 py-2 text-sm text-slate-100 transition hover:bg-white/12">Download</button>
              ) : null}
            </div>
          ))}
          {!reports.length ? <p className="text-slate-400">No reports generated yet.</p> : null}
        </div>
      </Card>
    </div>
  );
}
