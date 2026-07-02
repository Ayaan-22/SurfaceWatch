import { AppShell } from "@/components/layout/app-shell";
import { ScansTable } from "@/components/projects/scans-table";

export default async function ScansPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return (
    <AppShell>
      <div className="mb-6">
        <p className="text-sm text-slate-400">Project / Scans</p>
        <h1 className="text-3xl font-semibold text-white">Scan history</h1>
      </div>
      <ScansTable projectId={id} />
    </AppShell>
  );
}
