"use client";

import { Area, AreaChart, Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { riskTrend, severityData } from "@/lib/demo-data";

export function RiskTrendChart() {
  return (
    <ResponsiveContainer width="100%" height={260}>
      <AreaChart data={riskTrend}>
        <defs>
          <linearGradient id="riskFill" x1="0" x2="0" y1="0" y2="1">
            <stop offset="5%" stopColor="#27d3ff" stopOpacity={0.35} />
            <stop offset="95%" stopColor="#27d3ff" stopOpacity={0.02} />
          </linearGradient>
        </defs>
        <CartesianGrid stroke="rgba(148,163,184,0.12)" vertical={false} />
        <XAxis dataKey="date" stroke="#94a3b8" tickLine={false} axisLine={false} />
        <YAxis stroke="#94a3b8" tickLine={false} axisLine={false} domain={[0, 100]} />
        <Tooltip contentStyle={{ background: "#111827", border: "1px solid rgba(255,255,255,0.12)", borderRadius: 8 }} />
        <Area type="monotone" dataKey="score" stroke="#27d3ff" fill="url(#riskFill)" strokeWidth={2} />
      </AreaChart>
    </ResponsiveContainer>
  );
}

export function SeverityChart() {
  return (
    <ResponsiveContainer width="100%" height={260}>
      <BarChart data={severityData}>
        <CartesianGrid stroke="rgba(148,163,184,0.12)" vertical={false} />
        <XAxis dataKey="name" stroke="#94a3b8" tickLine={false} axisLine={false} />
        <YAxis stroke="#94a3b8" tickLine={false} axisLine={false} />
        <Tooltip contentStyle={{ background: "#111827", border: "1px solid rgba(255,255,255,0.12)", borderRadius: 8 }} />
        <Bar dataKey="value" fill="#4ade80" radius={[4, 4, 0, 0]} />
      </BarChart>
    </ResponsiveContainer>
  );
}
