import { AppShell } from "@/components/layout/app-shell";
import { NotificationsClient } from "@/components/notifications/notifications-client";

export default function NotificationsPage() {
  return (
    <AppShell>
      <div className="mb-6">
        <p className="text-sm text-slate-400">Workspace</p>
        <h1 className="text-3xl font-semibold text-white">Notifications</h1>
      </div>
      <NotificationsClient />
    </AppShell>
  );
}
