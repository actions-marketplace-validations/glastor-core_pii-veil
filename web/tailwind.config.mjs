/** @type {import('tailwindcss').Config} */
export default {
  content: ['./src/**/*.{astro,html,js,jsx,md,mdx,svelte,ts,tsx,vue}'],
  theme: {
    extend: {
      colors: {
        cyber: {
          dark: '#080c14',
          card: '#0f172a',
          border: '#1e293b',
          neon: '#00ff9d',
          neonHover: '#00df89',
          cyan: '#00e5ff',
          purple: '#a855f7',
          muted: '#94a3b8'
        }
      },
      fontFamily: {
        sans: ['"Red Hat Text"', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        display: ['"Red Hat Display"', '"Red Hat Text"', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['"Red Hat Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace']
      }
    },
  },
  plugins: [],
}
