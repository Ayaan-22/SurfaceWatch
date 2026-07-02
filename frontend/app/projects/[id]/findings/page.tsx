import { AppShell } from "@/components/layout/app-shell";
import { FindingsTable } from "@/components/projects/findings-table";

export default async function FindingsPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return (
    <AppShell>
      <div className="mb-6">
        <p className="text-sm text-slate-400">Project / Findings</p>
        <h1 className="text-3xl font-semibold text-white">Findings</h1>
      </div>
      <FindingsTable projectId={id} />
    </AppShell>
  );
}
