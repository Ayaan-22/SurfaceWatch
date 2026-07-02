"use client";

import { useEffect, useState } from "react";
import { Bell } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import { apiFetch, type Notification } from "@/lib/api";

export function NotificationsClient() {
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  async function load() {
    setNotifications(await apiFetch<Notification[]>("/notifications"));
  }

  useEffect(() => {
    load()
      .catch((err) => setError(err instanceof Error ? err.message : "Could not load notifications."))
      .finally(() => setLoading(false));
  }, []);

  async function markRead(id: string) {
    await apiFetch<Notification>(`/notifications/${id}/read`, { method: "PATCH" });
    await load();
  }

  return (
    <Card>
      {loading ? <p className="text-slate-400">Loading notifications...</p> : null}
      {error ? <p className="text-red-100">{error}</p> : null}
      <div className="space-y-3">
        {notifications.map((item) => (
          <div key={item.id} className="flex items-start justify-between gap-5 rounded-lg border border-white/10 bg-surface-950 p-4">
            <div className="flex gap-3">
              <Bell className="mt-1 text-cyan-200" size={18} />
              <div>
                <p className="font-medium text-white">{item.title}</p>
                <p className="mt-1 text-sm text-slate-400">{item.message}</p>
                <p className="mt-1 text-xs text-slate-500">{new Date(item.created_at).toLocaleString()}</p>
              </div>
            </div>
            <button onClick={() => markRead(item.id)} disabled={item.is_read} className="disabled:cursor-default">
              <Badge tone={item.is_read ? "info" : "medium"}>{item.is_read ? "Read" : "Unread"}</Badge>
            </button>
          </div>
        ))}
        {!loading && !notifications.length ? <p className="text-slate-400">No notifications yet.</p> : null}
      </div>
    </Card>
  );
}
