"use client";

import { Area, AreaChart, Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";

export type RiskTrendPoint = {
  date: string;
  score: number;
};

export type SeverityPoint = {
  name: string;
  value: number;
};

const emptyRiskTrend: RiskTrendPoint[] = [{ date: "No scans", score: 0 }];
const emptySeverityData: SeverityPoint[] = [
  { name: "Critical", value: 0 },
  { name: "High", value: 0 },
  { name: "Medium", value: 0 },
  { name: "Low", value: 0 },
  { name: "Info", value: 0 }
];

export function RiskTrendChart({ data }: { data: RiskTrendPoint[] }) {
  const chartData = data.length ? data : emptyRiskTrend;
  return (
    <ResponsiveContainer width="100%" height={260}>
      <AreaChart data={chartData}>
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

export function SeverityChart({ data }: { data: SeverityPoint[] }) {
  const chartData = data.length ? data : emptySeverityData;
  return (
    <ResponsiveContainer width="100%" height={260}>
      <BarChart data={chartData}>
        <CartesianGrid stroke="rgba(148,163,184,0.12)" vertical={false} />
        <XAxis dataKey="name" stroke="#94a3b8" tickLine={false} axisLine={false} />
        <YAxis stroke="#94a3b8" tickLine={false} axisLine={false} />
        <Tooltip contentStyle={{ background: "#111827", border: "1px solid rgba(255,255,255,0.12)", borderRadius: 8 }} />
        <Bar dataKey="value" fill="#4ade80" radius={[4, 4, 0, 0]} />
      </BarChart>
    </ResponsiveContainer>
  );
}
