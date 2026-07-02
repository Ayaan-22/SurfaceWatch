import { Radar } from "lucide-react";
import { LoginForm } from "@/components/auth/login-form";
import { Card } from "@/components/ui/card";

export default function LoginPage() {
  return (
    <main className="grid min-h-screen place-items-center bg-surface-950 px-5 text-slate-100">
      <Card className="w-full max-w-md">
        <div className="mb-7 flex items-center gap-3">
          <span className="grid h-10 w-10 place-items-center rounded-lg bg-cyan-300 text-slate-950"><Radar size={22} /></span>
          <div>
            <h1 className="font-semibold text-white">Welcome back</h1>
            <p className="text-sm text-slate-400">Demo: demo@surfacewatch.dev</p>
          </div>
        </div>
        <LoginForm />
        <p className="mt-5 text-center text-sm text-slate-400">Need an account? <a className="text-cyan-200" href="/register">Register</a></p>
      </Card>
    </main>
  );
}
