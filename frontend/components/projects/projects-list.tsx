"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Activity, Plus } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { apiFetch, type Project } from "@/lib/api";

export function ProjectsList() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    apiFetch<Project[]>("/projects")
      .then(setProjects)
      .catch((err) => setError(err instanceof Error ? err.message : "Could not load projects."))
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return <Card><p className="text-slate-400">Loading projects...</p></Card>;
  }

  if (error) {
    return (
      <Card>
        <p className="text-red-100">{error}</p>
        <Button href="/login" className="mt-4" variant="secondary">Login</Button>
      </Card>
    );
  }

  if (!projects.length) {
    return (
      <Card className="text-center">
        <Activity className="mx-auto mb-4 text-cyan-200" size={30} />
        <h2 className="text-xl font-semibold text-white">No projects yet</h2>
        <p className="mt-2 text-slate-400">Create an authorized domain scope before running scans.</p>
        <Button href="/projects/new" className="mt-5"><Plus size={17} /> New project</Button>
      </Card>
    );
  }

  return (
    <div className="grid gap-5 md:grid-cols-2 xl:grid-cols-3">
      {projects.map((item) => (
        <Link key={item.id} href={`/projects/${item.id}`}>
          <Card className="h-full transition hover:border-cyan-300/30 hover:bg-white/[0.07]">
            <div className="mb-5 flex items-start justify-between gap-4">
              <div>
                <h2 className="text-lg font-semibold text-white">{item.company_name}</h2>
                <p className="mt-1 text-sm text-slate-400">{item.main_domain}</p>
              </div>
              <Badge tone={item.risk_level}>{item.risk_level}</Badge>
            </div>
            <div className="grid grid-cols-2 gap-3 text-sm">
              <div className="rounded-md border border-white/10 bg-surface-950 p-3">
                <p className="text-slate-500">Risk score</p>
                <p className="mt-1 text-xl font-semibold text-white">{item.risk_score}</p>
              </div>
              <div className="rounded-md border border-white/10 bg-surface-950 p-3">
                <p className="text-slate-500">Frequency</p>
                <p className="mt-1 text-xl font-semibold capitalize text-white">{item.scan_frequency}</p>
              </div>
            </div>
          </Card>
        </Link>
      ))}
    </div>
  );
}
