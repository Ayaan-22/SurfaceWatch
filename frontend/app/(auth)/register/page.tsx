import { ShieldCheck } from "lucide-react";
import { RegisterForm } from "@/components/auth/register-form";
import { Card } from "@/components/ui/card";

export default function RegisterPage() {
  return (
    <main className="grid min-h-screen place-items-center bg-surface-950 px-5 text-slate-100">
      <Card className="w-full max-w-md">
        <ShieldCheck className="mb-5 text-emerald-200" size={32} />
        <h1 className="text-2xl font-semibold text-white">Create account</h1>
        <p className="mt-2 text-sm text-slate-400">Use SurfaceWatch only for authorized monitoring.</p>
        <RegisterForm />
      </Card>
    </main>
  );
}
