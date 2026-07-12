"use client";

import { useCallback, useEffect, useState } from "react";
import { Download, FileSpreadsheet, FileText } from "lucide-react";
import { Card } from "@/components/ui/card";
import { apiFetch, downloadReport, formatApiDateTime, type Report, type Scan } from "@/lib/api";

export function ReportsClient({ projectId }: { projectId: string }) {
  const [reports, setReports] = useState<Report[]>([]);
  const [scans, setScans] = useState<Scan[]>([]);
  const [selectedScanId, setSelectedScanId] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadReports = useCallback(async () => {
    setReports(await apiFetch<Report[]>(`/projects/${projectId}/reports`));
  }, [projectId]);

  const loadScans = useCallback(async () => {
    const scanRows = await apiFetch<Scan[]>(`/projects/${projectId}/scans`);
    setScans(scanRows);
    const reportable = scanRows.filter((scan) => scan.status === "completed" || scan.status === "partial");
    setSelectedScanId((current) => reportable.some((scan) => scan.id === current) ? current : reportable[0]?.id || "");
  }, [projectId]);

  useEffect(() => {
    Promise.all([loadReports(), loadScans()]).catch((err) => setError(err instanceof Error ? err.message : "Could not load reports."));
  }, [loadReports, loadScans]);

  const selectedScan = scans.find((scan) => scan.id === selectedScanId);
  const reportableScans = scans.filter((scan) => scan.status === "completed" || scan.status === "partial");

  function scanLabel(scan: Scan) {
    const scanDate = scan.finished_at ?? scan.started_at ?? scan.created_at;
    return `${scan.scan_profile} profile - ${formatApiDateTime(scanDate)} - ${scan.status}`;
  }

  function reportScanLabel(report: Report) {
    const scan = scans.find((row) => row.id === report.scan_id);
    if (scan) return scanLabel(scan);
    if (report.scan_profile && report.scan_date) {
      return `${report.scan_profile} profile - ${formatApiDateTime(report.scan_date)}`;
    }
    return report.scan_id ? `Scan ${report.scan_id}` : "Legacy project-wide report";
  }

  async function generate(type: "pdf" | "excel") {
    setError(null);
    if (!selectedScanId) {
      setError("Choose a scan before generating a report.");
      return;
    }
    setLoading(true);
    try {
      const report = await apiFetch<Report>(`/projects/${projectId}/reports/${type}`, {
        method: "POST",
        body: JSON.stringify({ scan_id: selectedScanId })
      });
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
      <Card>
        <label className="text-sm font-medium text-slate-200" htmlFor="report-scan">Report scan</label>
        <select
          id="report-scan"
          value={selectedScanId}
          onChange={(event) => setSelectedScanId(event.target.value)}
          className="mt-3 h-11 w-full rounded-md border border-white/10 bg-surface-950 px-3 text-sm text-slate-100 outline-none transition focus:border-cyan-300"
        >
          {reportableScans.map((scan) => (
            <option key={scan.id} value={scan.id}>{scanLabel(scan)}</option>
          ))}
        </select>
        {selectedScan ? (
          <p className="mt-3 text-sm text-slate-400">Exports will use scan {selectedScan.id} with {selectedScan.assets_scanned} processed targets, {selectedScan.findings_created} findings, and {selectedScan.coverage_percent}% coverage.</p>
        ) : (
          <p className="mt-3 text-sm text-slate-400">Run a scan before generating reports.</p>
        )}
      </Card>
      <div className="grid gap-5 md:grid-cols-2">
        <Card>
          <FileText className="mb-5 text-cyan-200" size={28} />
          <h2 className="text-lg font-semibold text-white">PDF executive report</h2>
          <p className="mt-3 leading-7 text-slate-400">Cover page, scan score summary, findings, recommendations, and authorization disclaimer.</p>
          <button disabled={loading || !selectedScanId} onClick={() => generate("pdf")} className="mt-6 inline-flex h-10 items-center justify-center gap-2 rounded-md border border-white/12 bg-white/8 px-4 text-sm font-semibold text-slate-100 transition hover:bg-white/12 disabled:opacity-60">
            <Download size={17} /> Generate PDF
          </button>
        </Card>
        <Card>
          <FileSpreadsheet className="mb-5 text-emerald-200" size={28} />
          <h2 className="text-lg font-semibold text-white">Excel workbook</h2>
          <p className="mt-3 leading-7 text-slate-400">Summary, assets, findings, ports, headers, SSL/TLS, technologies, and selected scan metadata sheets.</p>
          <button disabled={loading || !selectedScanId} onClick={() => generate("excel")} className="mt-6 inline-flex h-10 items-center justify-center gap-2 rounded-md border border-white/12 bg-white/8 px-4 text-sm font-semibold text-slate-100 transition hover:bg-white/12 disabled:opacity-60">
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
                <p className="text-sm text-slate-400">{reportScanLabel(report)}</p>
                <p className="text-sm text-slate-500">{formatApiDateTime(report.created_at)} - {report.status}</p>
                {report.error_message ? <p className="mt-1 text-sm text-red-200">{report.error_message}</p> : null}
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
