"use client";

import { useEffect, useState } from "react";
import { usePathname } from "next/navigation";
import { Bell, FileText, FolderKanban, LayoutDashboard, PanelLeftClose, PanelLeftOpen, Radar, Settings, ShieldCheck } from "lucide-react";
import Link from "next/link";
import { AuthGate, LogoutButton } from "@/components/auth/auth-gate";
import { WorkspaceTitle } from "@/components/layout/workspace-title";
import { Button } from "@/components/ui/button";
import { apiFetch, type Project } from "@/lib/api";
import { cn } from "@/lib/utils";

const PROJECT_PATH_PATTERN = /^\/projects\/([^/]+)/;
const SIDEBAR_COLLAPSED_KEY = "surfacewatch_sidebar_collapsed";

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const [firstProjectId, setFirstProjectId] = useState<string | null>(null);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);

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

  useEffect(() => {
    setSidebarCollapsed(window.localStorage.getItem(SIDEBAR_COLLAPSED_KEY) === "true");
  }, []);

  function toggleSidebar() {
    setSidebarCollapsed((collapsed) => {
      const next = !collapsed;
      window.localStorage.setItem(SIDEBAR_COLLAPSED_KEY, String(next));
      return next;
    });
  }

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
      <aside className={cn("fixed inset-y-0 left-0 hidden border-r border-white/10 bg-surface-900/96 px-3 py-4 transition-[width] duration-200 lg:block", sidebarCollapsed ? "w-20" : "w-60")}>
        <div className={cn("flex items-center justify-between gap-2", sidebarCollapsed && "flex-col")}>
        <Link href="/dashboard" className={cn("flex min-w-0 items-center gap-3 px-1", sidebarCollapsed && "justify-center")}>
          <span className="grid h-10 w-10 place-items-center rounded-lg bg-cyan-300 text-slate-950">
            <Radar size={22} />
          </span>
          <div className={cn("min-w-0", sidebarCollapsed && "hidden")}>
            <div className="font-semibold">SurfaceWatch</div>
            <div className="text-xs text-slate-400">Authorized ASM</div>
          </div>
        </Link>
        <button
          type="button"
          onClick={toggleSidebar}
          className="grid h-9 w-9 place-items-center rounded-md border border-white/10 text-slate-300 transition hover:bg-white/8 hover:text-white"
          aria-label={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
          title={sidebarCollapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          {sidebarCollapsed ? <PanelLeftOpen size={18} /> : <PanelLeftClose size={18} />}
        </button>
        </div>
        <nav className="mt-8 space-y-1">
          {nav.map((item) => (
            <Link
              key={item.key}
              href={item.href}
              title={sidebarCollapsed ? item.label : undefined}
              className={cn(
                "flex items-center gap-3 rounded-md px-3 py-2.5 text-sm text-slate-300 transition hover:bg-white/8 hover:text-white",
                sidebarCollapsed && "justify-center px-2"
              )}
            >
              <item.icon size={18} className="shrink-0" />
              <span className={cn(sidebarCollapsed && "sr-only")}>{item.label}</span>
            </Link>
          ))}
        </nav>
        <div className={cn("absolute bottom-5 left-3 right-3 rounded-lg border border-emerald-400/20 bg-emerald-500/10 text-sm text-emerald-100", sidebarCollapsed ? "p-3" : "p-4")}>
          <div className="mb-2 flex items-center gap-2 font-semibold">
            <ShieldCheck size={16} />
            <span className={cn(sidebarCollapsed && "sr-only")}>Authorized use only</span>
          </div>
          <p className={cn("text-xs leading-5 text-emerald-100/80", sidebarCollapsed && "sr-only")}>Only monitor domains and IPs you own or have written permission to assess.</p>
        </div>
      </aside>
      <main className={cn("transition-[padding] duration-200", sidebarCollapsed ? "lg:pl-20" : "lg:pl-60")}>
        <header className="sticky top-0 z-10 flex h-16 items-center justify-between border-b border-white/10 bg-surface-950/86 px-5 backdrop-blur">
          <WorkspaceTitle />
          <div className="flex items-center gap-3">
            <Button href="/projects/new" variant="secondary">New project</Button>
            <LogoutButton />
          </div>
        </header>
        <div key={pathname} className="page-enter px-5 py-6 lg:px-8">{children}</div>
      </main>
    </div>
    </AuthGate>
  );
}
