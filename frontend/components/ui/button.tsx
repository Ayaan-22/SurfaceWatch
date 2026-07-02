import Link from "next/link";
import { cn } from "@/lib/utils";

const base = "inline-flex h-10 items-center justify-center gap-2 rounded-md px-4 text-sm font-semibold transition focus:outline-none focus:ring-2 focus:ring-cyan-300/60";
const variants = {
  primary: "bg-cyan-300 text-slate-950 hover:bg-cyan-200",
  secondary: "border border-white/12 bg-white/8 text-slate-100 hover:bg-white/12",
  danger: "border border-red-400/40 bg-red-500/14 text-red-100 hover:bg-red-500/20"
};

export function Button({
  children,
  className,
  variant = "primary",
  href,
  type
}: {
  children: React.ReactNode;
  className?: string;
  variant?: keyof typeof variants;
  href?: string;
  type?: "button" | "submit";
}) {
  const classes = cn(base, variants[variant], className);
  if (href) {
    return (
      <Link href={href} className={classes}>
        {children}
      </Link>
    );
  }
  return (
    <button type={type ?? "button"} className={classes}>
      {children}
    </button>
  );
}
