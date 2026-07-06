"use client";

import { Radar } from "lucide-react";
import { Card } from "@/components/ui/card";
import { cn } from "@/lib/utils";

export function LoadingMark({ className }: { className?: string }) {
  return (
    <div className={cn("relative grid h-12 w-12 place-items-center", className)}>
      <span className="absolute inset-0 rounded-full border border-cyan-300/20" />
      <span className="absolute inset-1 rounded-full border-2 border-cyan-300/80 border-t-transparent animate-spin" />
      <span className="grid h-8 w-8 place-items-center rounded-lg bg-cyan-300 text-slate-950 shadow-lg shadow-cyan-950/40">
        <Radar size={18} />
      </span>
    </div>
  );
}

export function PageLoader({ title = "Loading workspace", detail = "Preparing live project data." }: { title?: string; detail?: string }) {
  return (
    <Card className="overflow-hidden">
      <div className="flex min-h-[260px] items-center justify-center">
        <div className="w-full max-w-md text-center">
          <LoadingMark className="mx-auto" />
          <h2 className="mt-5 text-xl font-semibold text-white">{title}</h2>
          <p className="mt-2 text-sm text-slate-400">{detail}</p>
          <div className="mt-6 space-y-3">
            <div className="mx-auto h-3 w-11/12 rounded-full bg-white/8 loading-shimmer" />
            <div className="mx-auto h-3 w-8/12 rounded-full bg-white/8 loading-shimmer" />
            <div className="mx-auto h-3 w-10/12 rounded-full bg-white/8 loading-shimmer" />
          </div>
        </div>
      </div>
    </Card>
  );
}

export function InlineLoader({ label = "Loading data" }: { label?: string }) {
  return (
    <div className="mb-4 flex items-center gap-3 rounded-lg border border-cyan-300/15 bg-cyan-300/8 px-4 py-3 text-sm text-cyan-100">
      <LoadingMark className="h-8 w-8" />
      <span>{label}</span>
    </div>
  );
}
