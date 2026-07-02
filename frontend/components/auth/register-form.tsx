"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { register } from "@/lib/api";

export function RegisterForm() {
  const router = useRouter();
  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function onSubmit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setLoading(true);
    try {
      await register(fullName, email, password);
      router.push("/projects/new");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Registration failed.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <form onSubmit={onSubmit} className="mt-7 space-y-4">
      <input value={fullName} onChange={(event) => setFullName(event.target.value)} className="h-11 w-full rounded-md border border-white/10 bg-surface-950 px-3 outline-none focus:border-cyan-300/60" placeholder="Full name" />
      <input value={email} onChange={(event) => setEmail(event.target.value)} className="h-11 w-full rounded-md border border-white/10 bg-surface-950 px-3 outline-none focus:border-cyan-300/60" placeholder="Email" />
      <input value={password} onChange={(event) => setPassword(event.target.value)} type="password" className="h-11 w-full rounded-md border border-white/10 bg-surface-950 px-3 outline-none focus:border-cyan-300/60" placeholder="Password" />
      {error ? <p className="rounded-md border border-red-400/30 bg-red-500/10 p-3 text-sm text-red-100">{error}</p> : null}
      <button disabled={loading} type="submit" className="inline-flex h-10 w-full items-center justify-center rounded-md bg-cyan-300 px-4 text-sm font-semibold text-slate-950 transition hover:bg-cyan-200 disabled:cursor-not-allowed disabled:opacity-60">
        {loading ? "Creating account..." : "Register"}
      </button>
    </form>
  );
}
