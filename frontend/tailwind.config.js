/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  darkMode: ['class', '[data-theme="dark"]'],
  theme: {
    extend: {
      colors: {
        bg: 'var(--bg)',
        s1: 'var(--s1)',
        s2: 'var(--s2)',
        bd: {
          DEFAULT: 'var(--bd)',
          strong: 'var(--bd-strong)',
        },
        tx: 'var(--tx)',
        mut: 'var(--mut)',
        dim: 'var(--dim)',
        cy: 'var(--cy)',
        bl: 'var(--bl)',
        am: 'var(--am)',
        ok: 'var(--ok)',
        bad: 'var(--bad)',
        inv: 'var(--inv)',
        emb: 'var(--emb)',
      },
      fontFamily: {
        display: ['"Bebas Neue"', 'sans-serif'],
        body: ['"Barlow"', 'sans-serif'],
        mono: ['"DM Mono"', 'monospace'],
      },
      borderRadius: {
        DEFAULT: '2px',
        sm: '2px',
        md: '2px',
        lg: '2px',
        full: '9999px',
        none: '0px',
      },
      boxShadow: {
        DEFAULT: 'none',
        sm: 'none',
        md: 'none',
        lg: 'none',
        xl: 'none',
        '2xl': 'none',
        inner: 'none',
        none: 'none',
      },
      lineHeight: {
        display: '0.95',
        body: '1.55',
      },
      maxWidth: {
        container: '1440px',
      },
    },
  },
  plugins: [],
};
