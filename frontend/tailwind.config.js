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
        // Primary brand color - bright blue from logo
        primary: {
          50: '#eff8ff',
          100: '#dbeefe',
          200: '#bfe3fe',
          300: '#93d1fd',
          400: '#60b6fa',
          500: '#3b95f6',  // Main accent blue
          600: '#2577eb',
          700: '#1d63d8',
          800: '#1e50af',
          900: '#1e458a',
        },
        // Secondary - slate/navy from logo
        secondary: {
          50: '#f8fafc',
          100: '#f1f5f9',
          200: '#e2e8f0',
          300: '#cbd5e1',
          400: '#94a3b8',
          500: '#64748b',
          600: '#475569',
          700: '#334155',
          800: '#1e293b',  // Main dark color from logo
          900: '#0f172a',
          950: '#020617',
        },
      },
    },
  },
  plugins: [],
}
