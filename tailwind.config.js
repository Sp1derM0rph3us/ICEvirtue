/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./web/**/*.html", "./web/**/*.js"],
  theme: {
    extend: {
      colors: {
        dark: '#000000',
        card: '#0d0d0d',
        accent: '#bc13fe',
        'accent-glow': 'rgba(188, 19, 254, 0.5)'
      },
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'Helvetica Neue', 'Arial', 'sans-serif'],
        mono: ['Space Mono', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'Liberation Mono', 'Courier New', 'monospace']
      },
    },
  },
  plugins: [],
}
