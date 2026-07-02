import { AppShell } from "@/components/layout/app-shell";
import { Card } from "@/components/ui/card";

export default function SettingsPage() {
  return (
    <AppShell>
      <div className="mb-6">
        <p className="text-sm text-slate-400">Project / Settings</p>
        <h1 className="text-3xl font-semibold text-white">Settings</h1>
      </div>
      <Card>
        <div className="grid gap-5 md:grid-cols-2">
          <label className="space-y-2 text-sm">
            <span className="text-slate-300">Scan frequency</span>
            <select className="h-11 w-full rounded-md border border-white/10 bg-surface-950 px-3 outline-none focus:border-cyan-300/60">
              <option>Weekly</option>
              <option>Manual</option>
              <option>Daily</option>
              <option>Monthly</option>
            </select>
          </label>
          <label className="space-y-2 text-sm">
            <span className="text-slate-300">Notification threshold</span>
            <select className="h-11 w-full rounded-md border border-white/10 bg-surface-950 px-3 outline-none focus:border-cyan-300/60">
              <option>High and critical</option>
              <option>Medium and above</option>
              <option>Critical only</option>
            </select>
          </label>
        </div>
      </Card>
    </AppShell>
  );
}
