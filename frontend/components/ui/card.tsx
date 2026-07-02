import { cn } from "@/lib/utils";

export function Card({ className, children }: { className?: string; children: React.ReactNode }) {
  return (
    <section className={cn("rounded-lg border border-white/10 bg-white/[0.045] p-5 shadow-glow backdrop-blur", className)}>
      {children}
    </section>
  );
}
