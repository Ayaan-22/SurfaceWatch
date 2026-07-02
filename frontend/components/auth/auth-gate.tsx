"use client";

import { useEffect, useState } from "react";
import { usePathname, useRouter } from "next/navigation";
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
    return <div className="p-8 text-slate-400">Checking session...</div>;
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
