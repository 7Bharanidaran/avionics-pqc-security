/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        aerospace: {
          bg: "#090d16",
          surface: "#111722",
          elevated: "#182030",
          border: "#1e293b",
          borderHighlight: "#2d3b52",
          text: "#f1f5f9",
          muted: "#94a3b8",
          dim: "#64748b",
          accent: "#38bdf8",
          accentHover: "#0ea5e9",
          success: "#22c55e",
          successBg: "rgba(34, 197, 94, 0.1)",
          warning: "#f59e0b",
          warningBg: "rgba(245, 158, 11, 0.1)",
          danger: "#ef4444",
          dangerBg: "rgba(239, 68, 68, 0.1)",
        },
      },
      fontFamily: {
        sans: [
          'Inter',
          '-apple-system',
          'BlinkMacSystemFont',
          '"Segoe UI"',
          'Roboto',
          'sans-serif',
        ],
        mono: [
          '"JetBrains Mono"',
          '"SF Mono"',
          'Menlo',
          'Monaco',
          'Consolas',
          'monospace',
        ],
      },
    },
  },
  plugins: [],
}
