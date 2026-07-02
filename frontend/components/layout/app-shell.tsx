"use client";

import { useEffect, useState } from "react";
import { usePathname } from "next/navigation";
import { Bell, FileText, FolderKanban, LayoutDashboard, Radar, Settings, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { AuthGate, LogoutButton } from "@/components/auth/auth-gate";
import { WorkspaceTitle } from "@/components/layout/workspace-title";
import { Button } from "@/components/ui/button";
import { apiFetch, type Project } from "@/lib/api";

const PROJECT_PATH_PATTERN = /^\/projects\/([^/]+)/;

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const [firstProjectId, setFirstProjectId] = useState<string | null>(null);

  useEffect(() => {
    const match = PROJECT_PATH_PATTERN.exec(pathname);
    if (!match?.[1]) {
      apiFetch<Project[]>("/projects")
        .then((projects) => {
          if (projects && projects[0]) {
            setFirstProjectId(projects[0].id);
          }
        })
        .catch(() => {});
    }
  }, [pathname]);

  const match = PROJECT_PATH_PATTERN.exec(pathname);
  const currentProjectId = match?.[1] || firstProjectId;

  const reportsHref = currentProjectId && currentProjectId !== "new"
    ? `/projects/${currentProjectId}/reports`
    : "/projects";

  const nav = [
    { key: "dashboard", label: "Dashboard", href: "/dashboard", icon: LayoutDashboard },
    { key: "projects", label: "Projects", href: "/projects", icon: FolderKanban },
    { key: "reports", label: "Reports", href: reportsHref, icon: FileText },
    { key: "notifications", label: "Notifications", href: "/notifications", icon: Bell },
    { key: "settings", label: "Settings", href: "/settings", icon: Settings }
  ];

  return (
    <AuthGate>
    <div className="min-h-screen bg-surface-950 text-slate-100">
      <aside className="fixed inset-y-0 left-0 hidden w-72 border-r border-white/10 bg-surface-900/96 px-4 py-5 lg:block">
        <Link href="/dashboard" className="flex items-center gap-3 px-2">
          <span className="grid h-10 w-10 place-items-center rounded-lg bg-cyan-300 text-slate-950">
            <Radar size={22} />
          </span>
          <div>
            <div className="font-semibold">SurfaceWatch</div>
            <div className="text-xs text-slate-400">Authorized ASM</div>
          </div>
        </Link>
        <nav className="mt-8 space-y-1">
          {nav.map((item) => (
            <Link key={item.key} href={item.href} className="flex items-center gap-3 rounded-md px-3 py-2.5 text-sm text-slate-300 transition hover:bg-white/8 hover:text-white">
              <item.icon size={18} />
              {item.label}
            </Link>
          ))}
        </nav>
        <div className="absolute bottom-5 left-4 right-4 rounded-lg border border-emerald-400/20 bg-emerald-500/10 p-4 text-sm text-emerald-100">
          <div className="mb-2 flex items-center gap-2 font-semibold">
            <ShieldCheck size={16} />
            Authorized use only
          </div>
          <p className="text-xs leading-5 text-emerald-100/80">Only monitor domains and IPs you own or have written permission to assess.</p>
        </div>
      </aside>
      <main className="lg:pl-72">
        <header className="sticky top-0 z-10 flex h-16 items-center justify-between border-b border-white/10 bg-surface-950/86 px-5 backdrop-blur">
          <WorkspaceTitle />
          <div className="flex items-center gap-3">
            <Button href="/projects/new" variant="secondary">New project</Button>
            <LogoutButton />
          </div>
        </header>
        <div className="px-5 py-6 lg:px-8">{children}</div>
      </main>
    </div>
    </AuthGate>
  );
}
