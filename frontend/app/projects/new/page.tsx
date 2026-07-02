import { AppShell } from "@/components/layout/app-shell";
import { ProjectForm } from "@/components/projects/project-form";

export default function NewProjectPage() {
  return (
    <AppShell>
      <div className="mb-6">
        <p className="text-sm text-slate-400">Projects</p>
        <h1 className="text-3xl font-semibold text-white">Create project</h1>
      </div>
      <ProjectForm />
    </AppShell>
  );
}
