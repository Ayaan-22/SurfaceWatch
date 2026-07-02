import { AppShell } from "@/components/layout/app-shell";
import { ScanDetailClient } from "@/components/projects/scan-detail-client";

export default async function ScanDetailPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return (
    <AppShell>
      <ScanDetailClient scanId={id} />
    </AppShell>
  );
}
