export const project = {
  id: "demo-project",
  company: "Northstar Demo Co.",
  domain: "northstar-demo.test",
  riskScore: 62,
  riskLevel: "High",
  lastScan: "2026-07-01 11:42",
  nextScan: "2026-07-08 11:42"
};

export const metrics = [
  { label: "Total assets", value: "18", delta: "+3", tone: "cyan" },
  { label: "Active subdomains", value: "12", delta: "+2", tone: "green" },
  { label: "Open ports", value: "21", delta: "+1", tone: "amber" },
  { label: "Critical/high", value: "4", delta: "+1", tone: "red" }
];

export const riskTrend = [
  { date: "Jun 01", score: 34 },
  { date: "Jun 08", score: 38 },
  { date: "Jun 15", score: 45 },
  { date: "Jun 22", score: 51 },
  { date: "Jul 01", score: 62 }
];

export const severityData = [
  { name: "Critical", value: 1 },
  { name: "High", value: 3 },
  { name: "Medium", value: 7 },
  { name: "Low", value: 11 },
  { name: "Info", value: 8 }
];

export const assets = [
  { asset: "northstar-demo.test", type: "Root domain", ip: "203.0.113.10", status: "active", ports: "80, 443", technologies: "Next.js, Cloudflare", risk: "Medium", firstSeen: "Jun 01", lastSeen: "Jul 01" },
  { asset: "api.northstar-demo.test", type: "Subdomain", ip: "203.0.113.11", status: "active", ports: "443", technologies: "Nginx, PHP", risk: "Low", firstSeen: "Jun 10", lastSeen: "Jul 01" },
  { asset: "dev.northstar-demo.test", type: "Subdomain", ip: "203.0.113.12", status: "active", ports: "3000, 22", technologies: "Express", risk: "High", firstSeen: "Jun 30", lastSeen: "Jul 01" },
  { asset: "old.northstar-demo.test", type: "Subdomain", ip: "-", status: "inactive", ports: "-", technologies: "Apache", risk: "Info", firstSeen: "Jun 02", lastSeen: "Jun 25" }
];

export const findings = [
  { title: "Development port exposed", severity: "High", category: "Exposed Services", asset: "dev.northstar-demo.test", status: "Open", lastSeen: "Jul 01" },
  { title: "Certificate expires soon", severity: "Medium", category: "SSL/TLS", asset: "northstar-demo.test", status: "Open", lastSeen: "Jul 01" },
  { title: "Missing HSTS header", severity: "Medium", category: "Security Headers", asset: "northstar-demo.test", status: "Open", lastSeen: "Jul 01" },
  { title: "X-Powered-By header exposed", severity: "Low", category: "Technology Exposure", asset: "dev.northstar-demo.test", status: "Accepted Risk", lastSeen: "Jul 01" }
];

export const changes = [
  { change: "New open port", asset: "dev.northstar-demo.test:3000", severity: "Medium", when: "12 min ago" },
  { change: "Risk score increased", asset: "northstar-demo.test", severity: "High", when: "12 min ago" },
  { change: "Certificate expiry changed", asset: "northstar-demo.test", severity: "Medium", when: "12 min ago" }
];

export const scans = [
  { id: "SW-20260701-001", status: "completed", started: "Jul 01, 11:38", duration: "4m 12s", assets: 18, findings: 6, score: 62 },
  { id: "SW-20260622-001", status: "completed", started: "Jun 22, 09:00", duration: "3m 48s", assets: 15, findings: 5, score: 51 },
  { id: "SW-20260615-001", status: "completed", started: "Jun 15, 09:00", duration: "3m 51s", assets: 14, findings: 4, score: 45 }
];
