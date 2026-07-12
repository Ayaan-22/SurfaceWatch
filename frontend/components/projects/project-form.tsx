"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { ShieldCheck } from "lucide-react";
import { Card } from "@/components/ui/card";
import { apiFetch, type Project } from "@/lib/api";

export function ProjectForm() {
  const router = useRouter();
  const defaultExpiry = new Date();
  defaultExpiry.setFullYear(defaultExpiry.getFullYear() + 1);
  const [companyName, setCompanyName] = useState("");
  const [mainDomain, setMainDomain] = useState("");
  const [description, setDescription] = useState("");
  const [scanFrequency, setScanFrequency] = useState("manual");
  const [authorizationConfirmed, setAuthorizationConfirmed] = useState(false);
  const [authorizationContact, setAuthorizationContact] = useState("");
  const [authorizationExpiresAt, setAuthorizationExpiresAt] = useState(defaultExpiry.toISOString().slice(0, 10));
  const [maxScanProfile, setMaxScanProfile] = useState<"safe" | "aggressive">("safe");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setLoading(true);
    try {
      const project = await apiFetch<Project>("/projects", {
        method: "POST",
        body: JSON.stringify({
          company_name: companyName,
          main_domain: mainDomain,
          description,
          scan_frequency: scanFrequency,
          authorization_confirmed: authorizationConfirmed,
          authorization_contact: authorizationContact,
          authorization_expires_at: authorizationExpiresAt ? `${authorizationExpiresAt}T23:59:59Z` : null,
          max_scan_profile: maxScanProfile
        })
      });
      router.push(`/projects/${project.id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Project creation failed.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card className="w-full">
      <form onSubmit={onSubmit} className="space-y-5">
        <div className="grid gap-5 md:grid-cols-2">
          <label className="space-y-2 text-sm">
            <span className="text-slate-300">Company name</span>
            <input value={companyName} onChange={(event) => setCompanyName(event.target.value)} className="h-11 w-full rounded-md border border-white/10 bg-surface-950 px-3 text-white outline-none focus:border-cyan-300/60" placeholder="Northstar Security" />
          </label>
          <label className="space-y-2 text-sm">
            <span className="text-slate-300">Main domain</span>
            <input value={mainDomain} onChange={(event) => setMainDomain(event.target.value)} className="h-11 w-full rounded-md border border-white/10 bg-surface-950 px-3 text-white outline-none focus:border-cyan-300/60" placeholder="example.com" />
          </label>
        </div>
        <label className="space-y-2 text-sm">
          <span className="text-slate-300">Description</span>
          <textarea value={description} onChange={(event) => setDescription(event.target.value)} className="min-h-28 w-full rounded-md border border-white/10 bg-surface-950 px-3 py-3 text-white outline-none focus:border-cyan-300/60" placeholder="External assets for the production environment." />
        </label>
        <label className="space-y-2 text-sm">
          <span className="text-slate-300">Scan frequency</span>
          <select value={scanFrequency} onChange={(event) => setScanFrequency(event.target.value)} className="h-11 w-full rounded-md border border-white/10 bg-surface-950 px-3 text-white outline-none focus:border-cyan-300/60">
            <option value="manual">Manual</option>
            <option value="daily">Daily</option>
            <option value="weekly">Weekly</option>
            <option value="monthly">Monthly</option>
          </select>
        </label>
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
        <label className="space-y-2 text-sm">
          <span className="text-slate-300">Maximum approved scan profile</span>
          <select value={maxScanProfile} onChange={(event) => setMaxScanProfile(event.target.value as "safe" | "aggressive")} className="h-11 w-full rounded-md border border-white/10 bg-surface-950 px-3 text-white outline-none focus:border-cyan-300/60">
            <option value="safe">Safe only</option>
            <option value="aggressive">Safe and aggressive</option>
          </select>
        </label>
        <label className="flex items-start gap-3 rounded-lg border border-emerald-400/20 bg-emerald-500/10 p-4 text-sm text-emerald-100">
          <input checked={authorizationConfirmed} onChange={(event) => setAuthorizationConfirmed(event.target.checked)} type="checkbox" className="mt-1 h-4 w-4 accent-emerald-300" />
          <span>
            <span className="mb-1 flex items-center gap-2 font-semibold"><ShieldCheck size={16} /> Authorization confirmed</span>
            I own this domain or have explicit written authorization to monitor its public exposure.
          </span>
        </label>
        {error ? <p className="rounded-md border border-red-400/30 bg-red-500/10 p-3 text-sm text-red-100">{error}</p> : null}
        <button disabled={loading} type="submit" className="inline-flex h-10 items-center justify-center rounded-md bg-cyan-300 px-4 text-sm font-semibold text-slate-950 transition hover:bg-cyan-200 disabled:cursor-not-allowed disabled:opacity-60">
          {loading ? "Creating..." : "Create project"}
        </button>
      </form>
    </Card>
  );
}
