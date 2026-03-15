/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      fontFamily: {
        mono:    ['"JetBrains Mono"', 'monospace'],
        display: ['"Syne"', 'sans-serif'],
        body:    ['"DM Sans"', 'sans-serif'],
      },
      colors: {
        bg:       '#0a0c14',
        surface:  '#0f1320',
        card:     '#141826',
        border:   '#1e2538',
        muted:    '#2a3147',
        subtle:   '#4a5578',
        text:     '#e2e8f0',
        dim:      '#8892a4',
        accent:   '#6366f1',
        'accent-dim': '#4f52c7',
        critical: '#ef4444',
        high:     '#f97316',
        medium:   '#eab308',
        low:      '#22c55e',
        info:     '#38bdf8',
      },
      backgroundImage: {
        'grid-pattern': `linear-gradient(rgba(99,102,241,0.03) 1px, transparent 1px),
                         linear-gradient(90deg, rgba(99,102,241,0.03) 1px, transparent 1px)`,
      },
      backgroundSize: {
        'grid': '40px 40px',
      },
      animation: {
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        'fade-in':    'fadeIn 0.3s ease-out',
        'slide-in':   'slideIn 0.3s ease-out',
      },
      keyframes: {
        fadeIn:  { from: { opacity: 0 }, to: { opacity: 1 } },
        slideIn: { from: { opacity: 0, transform: 'translateY(8px)' }, to: { opacity: 1, transform: 'translateY(0)' } },
      }
    },
  },
  plugins: [],
}
