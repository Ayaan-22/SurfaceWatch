import { ArrowUpRight } from "lucide-react";
import Link from "next/link";
import { Card } from "@/components/ui/card";

export function StatCard({ label, value, delta, href }: { label: string; value: string; delta: string; href?: string }) {
  const iconClasses = "inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-md border border-cyan-300/20 bg-cyan-300/10 text-cyan-100 transition hover:border-cyan-200/50 hover:bg-cyan-300/15 focus:outline-none focus:ring-2 focus:ring-cyan-300/60";

  return (
    <Card>
      <div className="flex items-start justify-between gap-4">
        <div>
          <p className="text-sm text-slate-400">{label}</p>
          <p className="mt-3 text-3xl font-semibold tracking-normal text-white">{value}</p>
        </div>
        {href ? (
          <Link href={href} aria-label={`Open ${label}`} className={iconClasses}>
            <ArrowUpRight size={17} />
          </Link>
        ) : (
          <span className={iconClasses}>
            <ArrowUpRight size={17} />
          </span>
        )}
      </div>
      <p className="mt-4 text-sm text-slate-400"><span className="text-cyan-200">{delta}</span> since last scan</p>
    </Card>
  );
}
