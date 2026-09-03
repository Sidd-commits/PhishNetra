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
        cyber: {
          950: '#070b14',
          900: '#0c1222',
          850: '#11192e',
          800: '#16203b',
          700: '#1f2d52',
          600: '#2d3f70',
          accent: '#00f2fe',
          threat: '#ff3366',
          warning: '#ffb300',
          safe: '#00e676'
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace']
      }
    },
  },
  plugins: [],
}
