import { AppShell } from "@/components/layout/app-shell";
import { AssetsTable } from "@/components/projects/assets-table";

export default async function AssetsPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return (
    <AppShell>
      <div className="mb-6">
        <p className="text-sm text-slate-400">Project / Assets</p>
        <h1 className="text-3xl font-semibold text-white">Asset inventory</h1>
      </div>
      <AssetsTable projectId={id} />
    </AppShell>
  );
}
