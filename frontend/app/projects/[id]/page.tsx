import { AppShell } from "@/components/layout/app-shell";
import { ProjectOverviewClient } from "@/components/projects/project-overview-client";

export default async function ProjectOverviewPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  return (
    <AppShell>
      <ProjectOverviewClient projectId={id} />
    </AppShell>
  );
}
