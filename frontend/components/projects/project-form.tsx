"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { ShieldCheck } from "lucide-react";
import { Card } from "@/components/ui/card";
import { apiFetch, type Project } from "@/lib/api";

export function ProjectForm() {
  const router = useRouter();
  const [companyName, setCompanyName] = useState("");
  const [mainDomain, setMainDomain] = useState("");
  const [description, setDescription] = useState("");
  const [scanFrequency, setScanFrequency] = useState("manual");
  const [authorizationConfirmed, setAuthorizationConfirmed] = useState(false);
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
          authorization_confirmed: authorizationConfirmed
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
    <Card className="max-w-3xl">
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
