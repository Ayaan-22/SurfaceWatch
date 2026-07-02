import { ShieldAlert } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";

export default function EthicalUsePage() {
  return (
    <main className="min-h-screen bg-surface-950 px-5 py-10 text-slate-100">
      <div className="mx-auto max-w-3xl">
        <Button href="/" variant="secondary">Back</Button>
        <Card className="mt-6">
          <ShieldAlert className="mb-5 text-emerald-200" size={32} />
          <h1 className="text-3xl font-semibold text-white">Ethical Use</h1>
          <p className="mt-4 leading-7 text-slate-300">
            SurfaceWatch is designed for safe monitoring of public assets you own or have explicit authorization to assess. It uses passive-first discovery, strict port limits, short timeouts, and non-destructive checks.
          </p>
          <div className="mt-6 space-y-3 text-slate-300">
            <p>No exploitation, brute force, credential attacks, destructive testing, or bypass attempts.</p>
            <p>Do not add domains, hosts, or IP addresses without permission from the asset owner.</p>
            <p>Keep scan frequency reasonable and honor applicable laws, contracts, and rules of engagement.</p>
          </div>
        </Card>
      </div>
    </main>
  );
}
