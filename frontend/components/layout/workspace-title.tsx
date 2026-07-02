"use client";

import { useEffect, useState } from "react";
import { usePathname } from "next/navigation";
import { apiFetch, type Project } from "@/lib/api";

const PROJECT_PATH_PATTERN = /^\/projects\/([^/]+)/;

export function WorkspaceTitle() {
  const pathname = usePathname();
  const [title, setTitle] = useState("SurfaceWatch");
  const [subtitle, setSubtitle] = useState("External Exposure Workspace");

  useEffect(() => {
    const match = PROJECT_PATH_PATTERN.exec(pathname);
    const projectId = match?.[1];

    if (!projectId || projectId === "new") {
      setTitle("SurfaceWatch");
      setSubtitle("External Exposure Workspace");
      return;
    }

    let cancelled = false;
    apiFetch<Project>(`/projects/${projectId}`)
      .then((project) => {
        if (cancelled) return;
        setTitle(project.company_name);
        setSubtitle(project.main_domain);
      })
      .catch(() => {
        if (cancelled) return;
        setTitle("SurfaceWatch");
        setSubtitle("External Exposure Workspace");
      });

    return () => {
      cancelled = true;
    };
  }, [pathname]);

  return (
    <div>
      <div className="text-sm text-slate-400">{title}</div>
      <div className="font-semibold">{subtitle}</div>
    </div>
  );
}
