import { ArrowUpRight } from "lucide-react";
import { Card } from "@/components/ui/card";

export function StatCard({ label, value, delta }: { label: string; value: string; delta: string }) {
  return (
    <Card>
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="text-sm text-slate-400">{label}</p>
          <p className="mt-3 text-3xl font-semibold tracking-normal text-white">{value}</p>
        </div>
        <span className="rounded-md border border-cyan-300/20 bg-cyan-300/10 p-2 text-cyan-100">
          <ArrowUpRight size={17} />
        </span>
      </div>
      <p className="mt-4 text-sm text-slate-400"><span className="text-cyan-200">{delta}</span> since last scan</p>
    </Card>
  );
}
