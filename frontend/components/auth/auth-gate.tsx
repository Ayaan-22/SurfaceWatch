"use client";

import { useEffect, useState } from "react";
import { usePathname, useRouter } from "next/navigation";
import { PageLoader } from "@/components/ui/page-loader";
import { clearToken, getToken } from "@/lib/api";

export function AuthGate({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const [ready, setReady] = useState(false);

  useEffect(() => {
    if (!getToken()) {
      router.replace(`/login?next=${encodeURIComponent(pathname)}`);
      return;
    }
    setReady(true);
  }, [pathname, router]);

  if (!ready) {
    return (
      <main className="min-h-screen bg-surface-950 p-6 text-slate-100">
        <PageLoader title="Checking session" detail="Verifying access before opening the workspace." />
      </main>
    );
  }
  return children;
}

export function LogoutButton() {
  const router = useRouter();
  return (
    <button
      onClick={() => {
        clearToken();
        router.push("/login");
      }}
      className="rounded-md border border-white/12 bg-white/8 px-3 py-2 text-sm text-slate-100 transition hover:bg-white/12"
    >
      Logout
    </button>
  );
}
