/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        soc: {
          bg: "#0b0f14",
          panel: "#111827",
          border: "#1f2937",
          text: "#e5e7eb",
          muted: "#9ca3af",
          accent: "#22d3ee",
        },
        severity: {
          critical: "#dc2626",
          high: "#ea580c",
          medium: "#d97706",
          low: "#2563eb",
          info: "#64748b",
        },
      },
    },
  },
  plugins: [],
}
