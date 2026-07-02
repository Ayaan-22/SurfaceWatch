import { AppShell } from "@/components/layout/app-shell";
import { Card } from "@/components/ui/card";

export default function WorkspaceSettingsPage() {
  return (
    <AppShell>
      <div className="mb-6">
        <p className="text-sm text-slate-400">Workspace</p>
        <h1 className="text-3xl font-semibold text-white">Settings</h1>
      </div>
      <Card>
        <div className="grid gap-5 md:grid-cols-2">
          <label className="space-y-2 text-sm">
            <span className="text-slate-300">API base URL</span>
            <input className="h-11 w-full rounded-md border border-white/10 bg-surface-950 px-3 outline-none focus:border-cyan-300/60" defaultValue="http://localhost:8000/api/v1" />
          </label>
          <label className="space-y-2 text-sm">
            <span className="text-slate-300">Default scan concurrency</span>
            <input className="h-11 w-full rounded-md border border-white/10 bg-surface-950 px-3 outline-none focus:border-cyan-300/60" defaultValue="5" />
          </label>
        </div>
      </Card>
    </AppShell>
  );
}
