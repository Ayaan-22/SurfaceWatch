import type { Config } from "tailwindcss";

const config: Config = {
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}", "./lib/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        surface: {
          950: "#070b12",
          900: "#0c1220",
          850: "#111827",
          800: "#172033",
          700: "#243149"
        },
        signal: {
          cyan: "#27d3ff",
          green: "#4ade80",
          amber: "#f59e0b",
          orange: "#f97316",
          red: "#ef4444"
        }
      },
      boxShadow: {
        glow: "0 0 32px rgba(39, 211, 255, 0.16)"
      }
    }
  },
  plugins: []
};

export default config;
