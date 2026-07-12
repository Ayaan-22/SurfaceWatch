"use client";

import { useEffect, useRef, useState } from "react";
import { RefreshCw, StopCircle } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import { PageLoader } from "@/components/ui/page-loader";
import {
  apiDateMs,
  apiFetch,
  formatApiDateTime,
  type Asset,
  type Change,
  type Scan,
  type ScanAssetResult,
  type ScanLog
} from "@/lib/api";

type JsonRecord = Record<string, unknown>;

const DIAGNOSTIC_GROUPS: { key: keyof ScanAssetResult; label: string }[] = [
  { key: "http_observations", label: "HTTP observations" },
  { key: "tls_observations", label: "TLS observations" },
  { key: "port_observations", label: "Port observations" },
  { key: "header_observations", label: "Header observations" },
  { key: "technology_observations", label: "Technology observations" },
  { key: "exposure_observations", label: "Exposure observations" },
  { key: "finding_observations", label: "Finding observations" },
  { key: "errors", label: "Errors" }
];

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
  return status === "pending" || status === "queued" || status === "claimed" || status === "running";
}

function asRecord(value: unknown): JsonRecord | null {
  return value !== null && typeof value === "object" && !Array.isArray(value) ? value as JsonRecord : null;
}

function firstDisplayValue(record: JsonRecord | null, keys: string[]) {
  if (!record) return null;
  for (const key of keys) {
    const value = record[key];
    if (typeof value === "string" && value.trim()) return value;
    if (typeof value === "number" || typeof value === "boolean") return String(value);
  }
  return null;
}

function prettyJson(value: unknown) {
  try {
    return JSON.stringify(value, null, 2) ?? String(value);
  } catch {
    return String(value);
  }
}

function scanRiskLevel(score: number) {
  if (score <= 20) return "low";
  if (score <= 50) return "medium";
  if (score <= 75) return "high";
  return "critical";
}

function statusTone(status: string) {
  const normalized = status.toLowerCase();
  if (normalized.includes("fail") || normalized.includes("error") || normalized.includes("blocked")) return "high";
  if (isActiveScan(normalized) || normalized.includes("partial")) return "info";
  return "low";
}

function hasMetadata(value: Scan["discovery_metadata"]) {
  if (Array.isArray(value)) return value.length > 0;
  return Boolean(value && Object.keys(value).length > 0);
}

function MetricCard({ label, value, detail, tone = "info" }: { label: string; value: string | number; detail: string; tone?: string }) {
  return (
    <Card>
      <p className="text-sm text-slate-400">{label}</p>
      <div className="mt-3 flex items-center gap-3">
        <p className="text-3xl font-semibold text-white">{value}</p>
        <Badge tone={tone}>{detail}</Badge>
      </div>
    </Card>
  );
}

function DiagnosticGroup({ label, items }: { label: string; items: unknown[] }) {
  return (
    <section className="rounded-md border border-white/10 bg-surface-950 p-3">
      <div className="mb-3 flex items-center justify-between gap-3">
        <h4 className="font-medium text-white">{label}</h4>
        <span className="text-xs text-slate-500">{items.length} recorded</span>
      </div>
      {items.length ? (
        <div className="space-y-2">
          {items.map((item, index) => (
            <pre key={index} className="max-h-72 overflow-auto whitespace-pre-wrap break-words rounded bg-black/25 p-3 text-xs leading-5 text-slate-300">{prettyJson(item)}</pre>
          ))}
        </div>
      ) : (
        <p className="text-sm text-slate-500">No observations recorded.</p>
      )}
    </section>
  );
}

export function ScanDetailClient({ scanId }: { scanId: string }) {
  const [scan, setScan] = useState<Scan | null>(null);
  const [assets, setAssets] = useState<Asset[]>([]);
  const [results, setResults] = useState<ScanAssetResult[]>([]);
  const [logs, setLogs] = useState<ScanLog[]>([]);
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
        const [logData, assetData, resultData, changeData] = await Promise.all([
          apiFetch<ScanLog[]>(`/scans/${scanId}/logs`),
          apiFetch<Asset[]>(`/projects/${scanData.project_id}/assets`),
          apiFetch<ScanAssetResult[]>(`/scans/${scanId}/results`),
          apiFetch<Change[]>(`/scans/${scanId}/changes`)
        ]);
        if (active) {
          setScan(scanData);
          setAssets(assetData);
          setResults(resultData);
          setLogs(logData);
          setChanges(changeData);
          setError(null);
        }
      } catch (err) {
        if (active) {
          setError(err instanceof Error ? err.message : "Could not load scan results.");
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

  if (loading) return <PageLoader title="Loading scan" detail="Gathering immutable target results, coverage, changes, and diagnostics." />;
  if (error && !scan) return <Card><p className="text-red-100">{error}</p></Card>;
  if (!scan) return null;

  const activeScan = isActiveScan(scan.status);
  const activeScanLabel = scan.status === "queued" || scan.status === "pending"
    ? "Scan queued"
    : scan.status === "claimed"
      ? "Worker claimed scan"
      : "Scanning in progress";
  const elapsedStart = scan.started_at ?? scan.created_at;
  const elapsedMs = activeScan ? nowMs - apiDateMs(elapsedStart) : 0;
  const assetsDiscovered = scan.assets_discovered ?? results.length;
  const assetsProcessed = scan.assets_scanned ?? results.filter((result) => result.scan_status !== "pending").length;
  const assetsFailed = scan.assets_failed ?? results.filter((result) => statusTone(result.scan_status) === "high").length;
  const checksCompleted = scan.checks_completed ?? 0;
  const checksFailed = scan.checks_failed ?? 0;
  const coveragePercent = Number.isFinite(scan.coverage_percent)
    ? Math.max(0, Math.min(100, scan.coverage_percent))
    : assetsDiscovered
      ? Math.round((assetsProcessed / assetsDiscovered) * 100)
      : 0;
  const riskLevel = scanRiskLevel(scan.risk_score);
  const findingObservations = results.flatMap((result) =>
    result.finding_observations.map((observation, index) => ({ result, observation, index }))
  );
  const outcomeReason = scan.partial_reason ?? scan.error_message;
  const hasRecordedFailures = assetsFailed > 0 || checksFailed > 0;

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="text-sm text-slate-400">Scan detail</p>
          <h1 className="break-all text-3xl font-semibold text-white">{scan.id}</h1>
          <p className="mt-2 text-sm capitalize text-slate-400">
            {scan.scan_profile} profile · {scan.trigger} trigger · attempt {scan.attempt_count} · {scan.started_at ? `started ${formatApiDateTime(scan.started_at)}` : "not started"}
          </p>
          {scan.heartbeat_at ? <p className="mt-1 text-xs text-slate-500">Last worker heartbeat: {formatApiDateTime(scan.heartbeat_at)}</p> : null}
        </div>
        <div className="flex flex-wrap items-center gap-3">
          {activeScan ? (
            <div className="inline-flex h-10 items-center gap-2 rounded-md border border-cyan-300/30 bg-cyan-300/10 px-3 text-sm font-medium text-cyan-100">
              <span className="h-2 w-2 animate-pulse rounded-full bg-cyan-300" />
              <RefreshCw className="h-4 w-4 animate-spin" />
              <span>{activeScanLabel}</span>
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
          <Badge tone={statusTone(scan.status)}>{scan.status}</Badge>
        </div>
      </div>

      {error ? <p className="rounded-md border border-red-400/30 bg-red-500/10 p-3 text-sm text-red-100">{error}</p> : null}
      {outcomeReason ? (
        <div className="rounded-md border border-amber-300/30 bg-amber-400/10 p-4 text-sm text-amber-100">
          <p className="font-semibold">This scan is not a fully clean result set.</p>
          <p className="mt-1">{outcomeReason}</p>
        </div>
      ) : !activeScan && hasRecordedFailures ? (
        <div className="rounded-md border border-amber-300/30 bg-amber-400/10 p-4 text-sm text-amber-100">
          The scan recorded {assetsFailed} failed target{assetsFailed === 1 ? "" : "s"} and {checksFailed} failed check{checksFailed === 1 ? "" : "s"}. Review target diagnostics before treating the result as complete.
        </div>
      ) : null}

      <Card>
        <div className="flex flex-wrap items-end justify-between gap-3">
          <div>
            <p className="text-sm text-slate-400">Observed scan coverage</p>
            <p className="mt-2 text-3xl font-semibold text-white">{coveragePercent.toFixed(1)}%</p>
          </div>
          <p className="text-sm text-slate-400">{assetsProcessed} processed / {assetsDiscovered} discovered</p>
        </div>
        <div className="mt-4 h-2 overflow-hidden rounded-full bg-surface-950">
          <div className="h-full rounded-full bg-cyan-300 transition-[width]" style={{ width: `${coveragePercent}%` }} />
        </div>
        <p className="mt-3 text-xs text-slate-500">Coverage is reported from persisted scan counters; failed targets and checks remain visible rather than being counted as successful.</p>
      </Card>

      <div className="grid gap-5 sm:grid-cols-2 xl:grid-cols-4">
        <MetricCard label="Targets discovered" value={assetsDiscovered} detail="scan scope" />
        <MetricCard label="Targets processed" value={assetsProcessed} detail="attempted" tone={assetsProcessed < assetsDiscovered ? "medium" : "low"} />
        <MetricCard label="Target failures" value={assetsFailed} detail="recorded" tone={assetsFailed ? "high" : "low"} />
        <MetricCard label="Known project assets" value={assets.length} detail="current inventory" />
        <MetricCard label="Checks completed" value={checksCompleted} detail="successful" tone="low" />
        <MetricCard label="Checks failed" value={checksFailed} detail="diagnostics" tone={checksFailed ? "high" : "low"} />
        <MetricCard label="Finding observations" value={findingObservations.length} detail="this scan" tone={findingObservations.length ? "medium" : "low"} />
        <MetricCard label="Scan risk score" value={scan.risk_score} detail={riskLevel} tone={riskLevel} />
      </div>

      <Card>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 className="text-lg font-semibold text-white">Discovery metadata</h2>
            <p className="mt-1 text-sm text-slate-400">Source coverage and discovery diagnostics persisted with this scan.</p>
          </div>
          <Badge tone={hasMetadata(scan.discovery_metadata) ? "info" : "medium"}>{hasMetadata(scan.discovery_metadata) ? "recorded" : "not recorded"}</Badge>
        </div>
        {hasMetadata(scan.discovery_metadata) ? (
          <pre className="mt-4 max-h-96 overflow-auto whitespace-pre-wrap break-words rounded-md bg-surface-950 p-4 text-xs leading-5 text-slate-300">{prettyJson(scan.discovery_metadata)}</pre>
        ) : (
          <p className="mt-4 text-sm text-slate-500">No discovery metadata was persisted for this scan.</p>
        )}
      </Card>

      <Card>
        <div className="mb-4">
          <h2 className="text-lg font-semibold text-white">Per-target scan results</h2>
          <p className="mt-1 text-sm text-slate-400">Immutable observations attached to this scan, including failures and partial target outcomes.</p>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[980px] text-left text-sm">
            <thead className="text-slate-400">
              <tr className="border-b border-white/10">
                {['Target', 'IPs', 'Discovery', 'Scan', 'Checks', 'Observations', 'Findings', 'Errors', 'Risk'].map((heading) => (
                  <th key={heading} className="py-3 pr-4 font-medium">{heading}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {results.map((result) => {
                const observations = result.http_observations.length
                  + result.tls_observations.length
                  + result.port_observations.length
                  + result.header_observations.length
                  + result.technology_observations.length
                  + result.exposure_observations.length;
                return (
                  <tr key={result.id} className="border-b border-white/6 text-slate-200">
                    <td className="py-4 pr-4">
                      <p className="font-medium text-white">{result.hostname}</p>
                      <p className="mt-1 text-xs text-slate-500">{result.source ?? "unknown source"}</p>
                    </td>
                    <td className="py-4 pr-4 text-xs">{result.ip_addresses.join(", ") || "-"}</td>
                    <td className="py-4 pr-4"><Badge tone={statusTone(result.discovery_status)}>{result.discovery_status}</Badge></td>
                    <td className="py-4 pr-4"><Badge tone={statusTone(result.scan_status)}>{result.scan_status}</Badge></td>
                    <td className="py-4 pr-4">{Object.keys(result.checks).length}</td>
                    <td className="py-4 pr-4">{observations}</td>
                    <td className="py-4 pr-4">{result.finding_observations.length}</td>
                    <td className="py-4 pr-4"><span className={result.errors.length ? "font-semibold text-red-200" : "text-slate-400"}>{result.errors.length}</span></td>
                    <td className="py-4 pr-4"><Badge tone={result.risk_level}>{result.risk_level}</Badge></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
          {!results.length ? <p className="py-6 text-slate-400">No target results have been persisted for this scan yet.</p> : null}
        </div>
      </Card>

      <Card>
        <h2 className="text-lg font-semibold text-white">Target diagnostics</h2>
        <p className="mt-1 text-sm text-slate-400">Expand a target to inspect every recorded check, observation, and error without project-wide mixing.</p>
        <div className="mt-4 space-y-3">
          {results.map((result) => (
            <details key={result.id} className="group rounded-md border border-white/10 bg-surface-950 p-4">
              <summary className="flex cursor-pointer list-none flex-wrap items-center justify-between gap-3">
                <span className="font-medium text-white">{result.hostname}</span>
                <span className="flex flex-wrap gap-2 text-xs text-slate-400">
                  <span>{Object.keys(result.checks).length} checks</span>
                  <span>{result.finding_observations.length} findings</span>
                  <span>{result.errors.length} errors</span>
                </span>
              </summary>
              <div className="mt-4 grid gap-4 xl:grid-cols-2">
                <section className="rounded-md border border-white/10 bg-black/20 p-3">
                  <h4 className="mb-3 font-medium text-white">Check outcomes</h4>
                  <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-words text-xs leading-5 text-slate-300">{prettyJson(result.checks)}</pre>
                </section>
                {DIAGNOSTIC_GROUPS.map(({ key, label }) => (
                  <DiagnosticGroup key={key} label={label} items={result[key] as unknown[]} />
                ))}
              </div>
            </details>
          ))}
          {!results.length ? <p className="text-sm text-slate-500">Target diagnostics will appear as the scanner persists results.</p> : null}
        </div>
      </Card>

      <Card>
        <div className="mb-4 flex flex-wrap items-end justify-between gap-3">
          <div>
            <h2 className="text-lg font-semibold text-white">Findings observed in this scan</h2>
            <p className="mt-1 text-sm text-slate-400">These are immutable finding observations from the selected scan, not the project&apos;s current finding backlog.</p>
          </div>
          <Badge tone={findingObservations.length ? "medium" : "low"}>{findingObservations.length} recorded</Badge>
        </div>
        <div className="space-y-2">
          {findingObservations.map(({ result, observation, index }) => {
            const record = asRecord(observation);
            const title = firstDisplayValue(record, ["title", "name", "finding", "message"]) ?? `Finding observation ${index + 1}`;
            const severity = firstDisplayValue(record, ["severity", "risk_level", "level"]) ?? "info";
            const category = firstDisplayValue(record, ["category", "check", "type"]) ?? "Uncategorized";
            return (
              <details key={`${result.id}-${index}`} className="rounded-md border border-white/10 bg-surface-950 p-3 text-sm">
                <summary className="flex cursor-pointer list-none flex-wrap items-center justify-between gap-3">
                  <div>
                    <p className="font-medium text-white">{title}</p>
                    <p className="mt-1 text-slate-400">{result.hostname} · {category}</p>
                  </div>
                  <Badge tone={severity}>{severity}</Badge>
                </summary>
                <pre className="mt-3 max-h-80 overflow-auto whitespace-pre-wrap break-words rounded bg-black/25 p-3 text-xs leading-5 text-slate-300">{prettyJson(observation)}</pre>
              </details>
            );
          })}
          {!findingObservations.length ? <p className="text-slate-400">No finding observations were recorded for this scan.</p> : null}
        </div>
      </Card>

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
        <h2 className="mb-4 text-lg font-semibold text-white">Logs</h2>
        <div className="space-y-2">
          {logs.map((log) => (
            <div key={log.id} className="rounded-md border border-white/10 bg-surface-950 p-3 text-sm">
              <span className="mr-3 text-slate-500">{formatApiDateTime(log.created_at)}</span>
              <span className={log.level === "error" ? "text-red-200" : log.level === "warning" ? "text-amber-200" : "text-cyan-100"}>{log.level}</span>
              <span className="ml-3 text-slate-300">{log.message}</span>
            </div>
          ))}
          {!logs.length ? <p className="text-slate-400">No logs recorded yet.</p> : null}
        </div>
      </Card>
    </div>
  );
}
