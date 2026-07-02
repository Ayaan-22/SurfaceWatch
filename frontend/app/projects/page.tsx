import { AppShell } from "@/components/layout/app-shell";
import { ProjectsList } from "@/components/projects/projects-list";
import { Button } from "@/components/ui/button";

export default function ProjectsPage() {
  return (
    <AppShell>
      <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="text-sm text-slate-400">Workspace</p>
          <h1 className="text-3xl font-semibold text-white">Projects</h1>
        </div>
        <Button href="/projects/new">New project</Button>
      </div>
      <ProjectsList />
    </AppShell>
  );
}
