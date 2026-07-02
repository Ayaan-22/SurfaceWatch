import { ArrowRight, FileText, LockKeyhole, Radar, ShieldCheck, Sparkles } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";

const features = [
  { title: "External asset inventory", text: "Track domains, subdomains, IPs, technologies, ports, and certificates over time.", icon: Radar },
  { title: "Risk-first findings", text: "Turn missing headers, expiring certificates, and exposed services into explainable priorities.", icon: ShieldCheck },
  { title: "Professional reports", text: "Export internship-ready PDF and Excel reports with scope, evidence, and recommendations.", icon: FileText }
];

export default function LandingPage() {
  return (
    <main className="min-h-screen overflow-hidden bg-surface-950 text-slate-100">
      <section className="surface-grid relative border-b border-white/10">
        <nav className="mx-auto flex max-w-7xl items-center justify-between px-5 py-5">
          <div className="flex items-center gap-3 font-semibold">
            <span className="grid h-10 w-10 place-items-center rounded-lg bg-cyan-300 text-slate-950"><Radar size={22} /></span>
            SurfaceWatch
          </div>
          <div className="flex items-center gap-3">
            <Button href="/login" variant="secondary">Login</Button>
            <Button href="/register">Register</Button>
          </div>
        </nav>
        <div className="mx-auto grid max-w-7xl gap-10 px-5 pb-16 pt-12 lg:grid-cols-[1fr_0.9fr] lg:items-center">
          <div>
            <div className="mb-5 inline-flex items-center gap-2 rounded-full border border-emerald-400/20 bg-emerald-500/10 px-3 py-1 text-sm text-emerald-100">
              <LockKeyhole size={15} /> Authorized domains and IPs only
            </div>
            <h1 className="max-w-4xl text-5xl font-semibold tracking-normal text-white md:text-7xl">SurfaceWatch</h1>
            <p className="mt-6 max-w-2xl text-lg leading-8 text-slate-300">
              Safe attack surface monitoring for small teams, security interns, and organizations that need clean visibility into public-facing exposure.
            </p>
            <div className="mt-8 flex flex-wrap gap-3">
              <Button href="/dashboard">Open demo dashboard <ArrowRight size={18} /></Button>
              <Button href="/ethical-use" variant="secondary">Ethical use policy</Button>
            </div>
          </div>
          <Card className="p-0">
            <div className="border-b border-white/10 p-5">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-sm text-slate-400">Northstar Demo Co.</p>
                  <p className="text-xl font-semibold">Exposure summary</p>
                </div>
                <span className="rounded-full border border-orange-400/40 bg-orange-500/12 px-3 py-1 text-sm text-orange-100">High</span>
              </div>
            </div>
            <div className="grid gap-4 p-5 md:grid-cols-2">
              {["18 assets", "21 open ports", "4 critical/high", "3 risky changes"].map((item) => (
                <div key={item} className="rounded-lg border border-white/10 bg-surface-950 p-4 text-lg font-semibold">{item}</div>
              ))}
            </div>
            <div className="border-t border-white/10 p-5">
              <div className="mb-3 flex items-center gap-2 text-sm text-cyan-100"><Sparkles size={16} /> Latest risky change</div>
              <p className="text-slate-300">dev.northstar-demo.test exposed port 3000 during the latest scan.</p>
            </div>
          </Card>
        </div>
      </section>
      <section className="mx-auto grid max-w-7xl gap-5 px-5 py-14 md:grid-cols-3">
        {features.map((feature) => (
          <Card key={feature.title}>
            <feature.icon className="mb-5 text-cyan-200" size={28} />
            <h2 className="text-lg font-semibold text-white">{feature.title}</h2>
            <p className="mt-3 leading-7 text-slate-400">{feature.text}</p>
          </Card>
        ))}
      </section>
    </main>
  );
}
