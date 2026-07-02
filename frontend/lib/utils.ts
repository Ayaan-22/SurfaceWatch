import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function riskTone(level: string) {
  switch (level.toLowerCase()) {
    case "critical":
      return "border-red-400/40 bg-red-500/12 text-red-100";
    case "high":
      return "border-orange-400/40 bg-orange-500/12 text-orange-100";
    case "medium":
      return "border-amber-400/40 bg-amber-500/12 text-amber-100";
    case "low":
      return "border-emerald-400/40 bg-emerald-500/12 text-emerald-100";
    default:
      return "border-slate-400/30 bg-slate-500/10 text-slate-200";
  }
}
