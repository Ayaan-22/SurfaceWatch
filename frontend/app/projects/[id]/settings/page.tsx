import { AppShell } from "@/components/layout/app-shell";
import { ProjectScopeSettings } from "@/components/projects/project-scope-settings";

export default async function SettingsPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return (
    <AppShell>
      <div className="mb-6">
        <p className="text-sm text-slate-400">Project / Settings</p>
        <h1 className="text-3xl font-semibold text-white">Settings</h1>
      </div>
      <ProjectScopeSettings projectId={id} />
    </AppShell>
  );
}
