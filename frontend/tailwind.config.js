/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        brand: {
          50: '#eff6ff',
          100: '#dbeafe',
          500: '#3b82f6',
          600: '#2563eb',
          700: '#1d4ed8',
          900: '#1e3a8a',
        },
        shield: {
          legit: '#10b981', // Emerald
          suspicious: '#f59e0b', // Amber
          phish: '#ef4444', // Red
          bg: '#0f172a',
          surface: '#1e293b',
          border: '#334155'
        }
      }
    },
  },
  plugins: [],
}