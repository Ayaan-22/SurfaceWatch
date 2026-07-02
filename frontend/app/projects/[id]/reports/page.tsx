import { AppShell } from "@/components/layout/app-shell";
import { ReportsClient } from "@/components/reports/reports-client";

export default async function ReportsPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return (
    <AppShell>
      <div className="mb-6">
        <p className="text-sm text-slate-400">Project / Reports</p>
        <h1 className="text-3xl font-semibold text-white">Reports</h1>
      </div>
      <ReportsClient projectId={id} />
    </AppShell>
  );
}
