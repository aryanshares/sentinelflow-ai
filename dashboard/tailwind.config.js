/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        mono: ['"JetBrains Mono"', '"Fira Code"', 'ui-monospace', 'monospace'],
        sans: ['"Inter"', 'system-ui', 'sans-serif'],
      },
      colors: {
        soc: {
          bg:       '#050810',
          surface:  '#0a0e1a',
          card:     '#0d1221',
          border:   '#1a2035',
          muted:    '#1e2640',
          accent:   '#3b82f6',
        },
      },
      animation: {
        'threat-pulse':   'threat-pulse 1s ease-in-out infinite',
        'amber-glow':     'amber-glow 2s ease-in-out infinite',
        'scan-line':      'scan-line 4s linear infinite',
        'fade-in-down':   'fade-in-down 0.3s ease-out forwards',
        'counter-tick':   'counter-tick 0.2s ease-out',
        'border-flow':    'border-flow 3s linear infinite',
      },
      keyframes: {
        'threat-pulse': {
          '0%, 100%': {
            boxShadow: '0 0 0 0 rgba(239,68,68,0.0), inset 0 0 0 1px rgba(239,68,68,0.6)',
          },
          '50%': {
            boxShadow: '0 0 20px 4px rgba(239,68,68,0.35), inset 0 0 0 1px rgba(239,68,68,1)',
          },
        },
        'amber-glow': {
          '0%, 100%': { boxShadow: '0 0 6px rgba(245,158,11,0.2)' },
          '50%':       { boxShadow: '0 0 18px rgba(245,158,11,0.5)' },
        },
        'scan-line': {
          '0%':   { transform: 'translateY(-100%)' },
          '100%': { transform: 'translateY(100vh)' },
        },
        'fade-in-down': {
          '0%':   { opacity: '0', transform: 'translateY(-12px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        'counter-tick': {
          '0%':   { transform: 'scale(1.15)', color: '#60a5fa' },
          '100%': { transform: 'scale(1)' },
        },
        'border-flow': {
          '0%':   { backgroundPosition: '0% 50%' },
          '50%':  { backgroundPosition: '100% 50%' },
          '100%': { backgroundPosition: '0% 50%' },
        },
      },
      backgroundImage: {
        'grid-pattern':
          'linear-gradient(rgba(59,130,246,0.04) 1px, transparent 1px), linear-gradient(90deg, rgba(59,130,246,0.04) 1px, transparent 1px)',
        'radial-glow':
          'radial-gradient(ellipse at center, rgba(59,130,246,0.08) 0%, transparent 70%)',
      },
      backgroundSize: {
        'grid': '40px 40px',
      },
    },
  },
  plugins: [],
}
