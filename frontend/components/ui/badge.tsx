import { cn, riskTone } from "@/lib/utils";

export function Badge({ children, tone = "info" }: { children: React.ReactNode; tone?: string }) {
  return (
    <span className={cn("inline-flex items-center rounded-full border px-2.5 py-1 text-xs font-medium", riskTone(tone))}>
      {children}
    </span>
  );
}
