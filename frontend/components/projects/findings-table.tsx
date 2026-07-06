"use client";

import { useEffect, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import { InlineLoader } from "@/components/ui/page-loader";
import { findings as demoFindings } from "@/lib/demo-data";
import { apiFetch, formatApiDate, formatApiDateTime, type Finding, type FindingNote } from "@/lib/api";

function StatTile({ label, value, detail, tone = "default" }: { label: string; value: number | string; detail: string; tone?: "default" | "warn" | "bad" | "muted" }) {
  const toneClass =
    tone === "bad"
      ? "border-red-300/25 bg-red-400/8"
      : tone === "warn"
        ? "border-amber-300/25 bg-amber-300/8"
        : tone === "muted"
          ? "border-slate-400/20 bg-slate-400/8"
          : "border-white/10 bg-white/[0.045]";

  return (
    <div className={`rounded-lg border p-4 ${toneClass}`}>
      <p className="text-sm text-slate-400">{label}</p>
      <p className="mt-2 text-2xl font-semibold text-white">{value}</p>
      <p className="mt-1 text-xs text-slate-500">{detail}</p>
    </div>
  );
}

export function FindingsTable({ projectId }: { projectId?: string }) {
  const [apiFindings, setApiFindings] = useState<Finding[] | null>(null);
  const [loading, setLoading] = useState(Boolean(projectId));
  const [error, setError] = useState<string | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [notes, setNotes] = useState<FindingNote[]>([]);
  const [newNote, setNewNote] = useState("");

  useEffect(() => {
    if (!projectId) return;
    apiFetch<Finding[]>(`/projects/${projectId}/findings`)
      .then(setApiFindings)
      .catch((err) => setError(err instanceof Error ? err.message : "Could not load findings."))
      .finally(() => setLoading(false));
  }, [projectId]);

  const rows = apiFindings
    ? apiFindings.map((finding) => ({
        id: finding.id,
        canUpdate: true,
        title: finding.title,
        severity: finding.severity,
        category: finding.category,
        asset: finding.asset_hostname ?? finding.asset_id ?? "Asset",
        status: finding.status,
        lastSeen: formatApiDate(finding.last_seen_at),
        confidence: finding.confidence,
        slaDue: finding.sla_due_at ? formatApiDate(finding.sla_due_at) : "-"
      }))
    : demoFindings.map((finding, index) => ({
        id: `demo-${index}-${finding.title}`,
        canUpdate: false,
        slaDue: "-",
        ...finding
      }));

  const openFindings = rows.filter((row) => row.status.toLowerCase() === "open").length;
  const criticalHighFindings = rows.filter((row) => ["critical", "high"].includes(row.severity.toLowerCase())).length;
  const mediumFindings = rows.filter((row) => row.severity.toLowerCase() === "medium").length;
  const closedOrAccepted = rows.filter((row) => ["accepted_risk", "accepted risk", "fixed", "false_positive", "false positive"].includes(row.status.toLowerCase())).length;
  const affectedAssets = new Set(rows.map((row) => row.asset).filter((asset) => asset && asset !== "Asset")).size;

  async function updateStatus(findingId: string, status: string) {
    await apiFetch<Finding>(`/findings/${findingId}/status`, {
      method: "PATCH",
      body: JSON.stringify({ status })
    });
    if (projectId) {
      setApiFindings(await apiFetch<Finding[]>(`/projects/${projectId}/findings`));
    }
  }

  async function openFinding(findingId: string) {
    const [finding, findingNotes] = await Promise.all([
      apiFetch<Finding>(`/findings/${findingId}`),
      apiFetch<FindingNote[]>(`/findings/${findingId}/notes`)
    ]);
    setSelectedFinding(finding);
    setNotes(findingNotes);
  }

  async function addNote() {
    if (!selectedFinding || !newNote.trim()) return;
    await apiFetch<FindingNote>(`/findings/${selectedFinding.id}/notes`, {
      method: "POST",
      body: JSON.stringify({ note: newNote.trim() })
    });
    setNewNote("");
    setNotes(await apiFetch<FindingNote[]>(`/findings/${selectedFinding.id}/notes`));
  }

  return (
    <div className="space-y-5">
      <div className="grid gap-4 md:grid-cols-5">
        <StatTile label="Total findings" value={rows.length} detail="All findings in this project" />
        <StatTile label="Open" value={openFindings} detail="Still requiring action" tone={openFindings ? "warn" : "default"} />
        <StatTile label="Critical / high" value={criticalHighFindings} detail="Highest priority exposure" tone={criticalHighFindings ? "bad" : "default"} />
        <StatTile label="Medium" value={mediumFindings} detail="Important hardening work" tone={mediumFindings ? "warn" : "default"} />
        <StatTile label="Affected assets" value={affectedAssets} detail="Unique assets with findings" tone="muted" />
      </div>
      <Card>
        {loading ? <InlineLoader label="Loading findings" /> : null}
        {error ? <p className="mb-4 rounded-md border border-red-400/30 bg-red-500/10 p-3 text-sm text-red-100">{error}</p> : null}
        <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
          <p className="text-sm text-slate-400">{closedOrAccepted} accepted, fixed, or false-positive findings</p>
          <div className="grid w-full gap-3 md:w-auto md:grid-cols-4">
            {["Search findings", "Severity", "Category", "Status"].map((label) => (
              <input key={label} className="h-10 rounded-md border border-white/10 bg-surface-950 px-3 text-sm outline-none focus:border-cyan-300/60" placeholder={label} />
            ))}
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full min-w-[860px] text-left text-sm">
            <thead className="text-slate-400">
              <tr className="border-b border-white/10">
                {["Finding", "Severity", "Category", "Asset", "Status", "Last seen", "SLA", "Details"].map((heading) => (
                  <th key={heading} className="py-3 pr-4 font-medium">{heading}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rows.map((row) => (
                <tr key={row.id} className="border-b border-white/6 text-slate-200">
                  <td className="py-4 pr-4 font-medium text-white">{row.title}</td>
                  <td className="py-4 pr-4"><Badge tone={row.severity}>{row.severity}</Badge></td>
                  <td className="py-4 pr-4">{row.category}</td>
                  <td className="py-4 pr-4">{row.asset}</td>
                  <td className="py-4 pr-4">
                    {row.canUpdate ? (
                      <select value={row.status} onChange={(event) => updateStatus(row.id, event.target.value)} className="h-9 rounded-md border border-white/10 bg-surface-950 px-2 text-xs text-white outline-none">
                        <option value="open">open</option>
                        <option value="accepted_risk">accepted_risk</option>
                        <option value="fixed">fixed</option>
                        <option value="false_positive">false_positive</option>
                      </select>
                    ) : (
                      row.status
                    )}
                  </td>
                  <td className="py-4 pr-4">{row.lastSeen}</td>
                  <td className="py-4 pr-4">{row.slaDue ?? "-"}</td>
                  <td className="py-4 pr-4">
                    {row.canUpdate ? (
                      <button onClick={() => openFinding(row.id)} className="rounded-md border border-white/10 px-3 py-1.5 text-xs text-cyan-100 hover:bg-white/8">Open</button>
                    ) : (
                      "-"
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {!loading && !rows.length ? <p className="py-6 text-slate-400">No findings yet. Run a safe scan to assess the project.</p> : null}
        </div>
      </Card>
      {selectedFinding ? (
        <div className="fixed inset-0 z-50 grid place-items-center bg-black/70 p-5">
          <div className="max-h-[90vh] w-full max-w-3xl overflow-y-auto rounded-lg border border-white/10 bg-surface-900 p-6 shadow-glow">
            <div className="mb-5 flex items-start justify-between gap-4">
              <div>
                <p className="text-sm text-slate-400">Finding detail</p>
                <h2 className="text-2xl font-semibold text-white">{selectedFinding.title}</h2>
              </div>
              <button onClick={() => setSelectedFinding(null)} className="rounded-md border border-white/10 px-3 py-1.5 text-sm text-slate-200 hover:bg-white/8">Close</button>
            </div>
            <div className="grid gap-4 md:grid-cols-3">
              <Card><p className="text-sm text-slate-400">Severity</p><div className="mt-3"><Badge tone={selectedFinding.severity}>{selectedFinding.severity}</Badge></div></Card>
              <Card><p className="text-sm text-slate-400">Category</p><p className="mt-3 font-semibold text-white">{selectedFinding.category}</p></Card>
              <Card><p className="text-sm text-slate-400">Status</p><p className="mt-3 font-semibold text-white">{selectedFinding.status}</p></Card>
              <Card><p className="text-sm text-slate-400">Confidence</p><p className="mt-3 font-semibold text-white">{selectedFinding.confidence}</p></Card>
              <Card><p className="text-sm text-slate-400">CVSS</p><p className="mt-3 font-semibold text-white">{selectedFinding.cvss_score ?? "n/a"}</p></Card>
              <Card><p className="text-sm text-slate-400">SLA due</p><p className="mt-3 font-semibold text-white">{selectedFinding.sla_due_at ? formatApiDate(selectedFinding.sla_due_at) : "n/a"}</p></Card>
            </div>
            <div className="mt-5 space-y-4 text-sm leading-6 text-slate-300">
              <section><h3 className="mb-2 font-semibold text-white">Description</h3><p>{selectedFinding.description}</p></section>
              <section><h3 className="mb-2 font-semibold text-white">Business impact</h3><p>{selectedFinding.business_impact ?? "Not specified."}</p></section>
              <section><h3 className="mb-2 font-semibold text-white">Recommendation</h3><p>{selectedFinding.recommendation ?? "Review and remediate according to policy."}</p></section>
              <section><h3 className="mb-2 font-semibold text-white">Evidence</h3><pre className="overflow-x-auto rounded-md bg-surface-950 p-3 text-xs text-slate-300">{JSON.stringify(selectedFinding.evidence ?? {}, null, 2)}</pre></section>
            </div>
            <div className="mt-6">
              <h3 className="mb-3 font-semibold text-white">Notes</h3>
              <div className="space-y-2">
                {notes.map((note) => (
                  <div key={note.id} className="rounded-md border border-white/10 bg-surface-950 p-3 text-sm text-slate-300">
                    <p>{note.note}</p>
                    <p className="mt-1 text-xs text-slate-500">{formatApiDateTime(note.created_at)}</p>
                  </div>
                ))}
                {!notes.length ? <p className="text-sm text-slate-500">No notes yet.</p> : null}
              </div>
              <div className="mt-3 flex gap-2">
                <input value={newNote} onChange={(event) => setNewNote(event.target.value)} className="h-10 flex-1 rounded-md border border-white/10 bg-surface-950 px-3 text-sm outline-none focus:border-cyan-300/60" placeholder="Add a note..." />
                <button onClick={addNote} className="rounded-md bg-cyan-300 px-4 text-sm font-semibold text-slate-950 hover:bg-cyan-200">Add</button>
              </div>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
