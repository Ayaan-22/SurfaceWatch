"use client";

import { useCallback, useEffect, useState } from "react";
import { RefreshCw, Save } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { InlineLoader } from "@/components/ui/page-loader";
import { apiFetch, parseApiDate, type Project } from "@/lib/api";

function dateInputValue(value?: string | null) {
  return value ? parseApiDate(value).toISOString().slice(0, 10) : "";
}

export function ProjectScopeSettings({ projectId }: { projectId: string }) {
  const [project, setProject] = useState<Project | null>(null);
  const [scanFrequency, setScanFrequency] = useState("manual");
  const [authorizationContact, setAuthorizationContact] = useState("");
  const [authorizationExpiresAt, setAuthorizationExpiresAt] = useState("");
  const [maxScanProfile, setMaxScanProfile] = useState<"safe" | "aggressive">("safe");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  const loadProject = useCallback(async () => {
    const projectData = await apiFetch<Project>(`/projects/${projectId}`);
    setProject(projectData);
    setScanFrequency(projectData.scan_frequency);
    setAuthorizationContact(projectData.authorization_contact ?? "");
    setAuthorizationExpiresAt(dateInputValue(projectData.authorization_expires_at));
    setMaxScanProfile(projectData.max_scan_profile === "aggressive" ? "aggressive" : "safe");
  }, [projectId]);

  useEffect(() => {
    let active = true;
    async function load() {
      try {
        await loadProject();
        if (active) setError(null);
      } catch (err) {
        if (active) setError(err instanceof Error ? err.message : "Could not load project scope.");
      } finally {
        if (active) setLoading(false);
      }
    }
    load();
    return () => {
      active = false;
    };
  }, [loadProject]);

  async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setSaved(false);
    setSaving(true);
    try {
      const updatedProject = await apiFetch<Project>(`/projects/${projectId}`, {
        method: "PATCH",
        body: JSON.stringify({
          scan_frequency: scanFrequency,
          authorization_contact: authorizationContact,
          authorization_expires_at: authorizationExpiresAt ? `${authorizationExpiresAt}T23:59:59Z` : null,
          max_scan_profile: maxScanProfile
        })
      });
      setProject(updatedProject);
      setSaved(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not update project scope.");
    } finally {
      setSaving(false);
    }
  }

  if (loading) {
    return (
      <Card>
        <InlineLoader label="Loading project scope" />
      </Card>
    );
  }

  return (
    <Card>
      {project ? (
        <div className="mb-5">
          <p className="text-sm text-slate-400">Authorized scope</p>
          <p className="mt-2 text-lg font-semibold text-white">{project.main_domain}</p>
        </div>
      ) : null}
      <form onSubmit={onSubmit} className="space-y-5">
        <div className="grid gap-5 md:grid-cols-2">
          <label className="space-y-2 text-sm">
            <span className="text-slate-300">Scan frequency</span>
            <select value={scanFrequency} onChange={(event) => setScanFrequency(event.target.value)} className="h-11 w-full rounded-md border border-white/10 bg-surface-950 px-3 outline-none focus:border-cyan-300/60">
              <option value="manual">Manual</option>
              <option value="daily">Daily</option>
              <option value="weekly">Weekly</option>
              <option value="monthly">Monthly</option>
            </select>
          </label>
          <label className="space-y-2 text-sm">
            <span className="text-slate-300">Maximum approved scan profile</span>
            <select value={maxScanProfile} onChange={(event) => setMaxScanProfile(event.target.value as "safe" | "aggressive")} className="h-11 w-full rounded-md border border-white/10 bg-surface-950 px-3 outline-none focus:border-cyan-300/60">
              <option value="safe">Safe only</option>
              <option value="aggressive">Safe and aggressive</option>
            </select>
          </label>
        </div>
        <div className="grid gap-5 md:grid-cols-3">
          <label className="space-y-2 text-sm md:col-span-2">
            <span className="text-slate-300">Authorization contact</span>
            <input value={authorizationContact} onChange={(event) => setAuthorizationContact(event.target.value)} className="h-11 w-full rounded-md border border-white/10 bg-surface-950 px-3 text-white outline-none focus:border-cyan-300/60" placeholder="security@example.com or engagement owner" />
          </label>
          <label className="space-y-2 text-sm">
            <span className="text-slate-300">Authorization expiry</span>
            <input value={authorizationExpiresAt} onChange={(event) => setAuthorizationExpiresAt(event.target.value)} type="date" className="h-11 w-full rounded-md border border-white/10 bg-surface-950 px-3 text-white outline-none focus:border-cyan-300/60" />
          </label>
        </div>
        {error ? <p className="rounded-md border border-red-400/30 bg-red-500/10 p-3 text-sm text-red-100">{error}</p> : null}
        {saved ? <p className="rounded-md border border-emerald-400/30 bg-emerald-500/10 p-3 text-sm text-emerald-100">Project scope updated.</p> : null}
        <div className="flex flex-wrap gap-3">
          <button disabled={saving} type="submit" className="inline-flex h-10 items-center justify-center gap-2 rounded-md bg-cyan-300 px-4 text-sm font-semibold text-slate-950 transition hover:bg-cyan-200 disabled:cursor-not-allowed disabled:opacity-60">
            {saving ? <RefreshCw className="animate-spin" size={17} /> : <Save size={17} />}
            {saving ? "Saving..." : "Save scope"}
          </button>
          <Button href={`/projects/${projectId}`} variant="secondary">Back to overview</Button>
        </div>
      </form>
    </Card>
  );
}
