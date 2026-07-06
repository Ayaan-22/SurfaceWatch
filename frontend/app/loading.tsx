import { PageLoader } from "@/components/ui/page-loader";

export default function Loading() {
  return (
    <main className="min-h-screen bg-surface-950 p-6 text-slate-100">
      <PageLoader title="Loading SurfaceWatch" detail="Opening the next workspace view." />
    </main>
  );
}
