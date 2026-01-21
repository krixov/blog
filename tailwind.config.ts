import type { Config } from "tailwindcss"

export default {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/layouts/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      fontFamily: {
        sans: ['JetBrains Mono', 'monospace'],
        mono: ['JetBrains Mono', 'monospace'],
      },
      typography: {
        DEFAULT: {
          css: {
            maxWidth: 'none',
            color: 'inherit',
            fontFamily: 'JetBrains Mono, monospace',
            h1: {
              fontWeight: '700',
              letterSpacing: '-0.025em',
            },
            h2: {
              fontWeight: '600',
              letterSpacing: '-0.025em',
            },
            h3: {
              fontWeight: '600',
              letterSpacing: '-0.025em',
            },
            'code::before': {
              content: '""',
            },
            'code::after': {
              content: '""',
            },
            
          },
        },
      },
    },
  },
  plugins: [
    require('@tailwindcss/typography'),
  ],
} satisfies Config
