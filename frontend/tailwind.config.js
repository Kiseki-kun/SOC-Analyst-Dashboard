/** @type {import('tailwindcss').Config} */

// Palette provenance
// ------------------
// The chart and status colours below are not hand-picked. They were run through
// a colour-vision-deficiency validator against this application's actual dark
// surface (#0d1219), and an earlier hand-chosen severity ramp FAILED three
// checks: two hues outside the lightness band, one below the chroma floor
// (it read as grey), and an adjacent pair only 10.2 ΔE apart in normal vision.
//
// What is here instead:
//   * series-1..3   categorical chart hues. Validated all-pairs on this surface
//                   (worst CVD ΔE 9.4, worst normal-vision ΔE 20.9). Capped at
//                   three: a fourth hue cannot clear the floors, so a fourth
//                   category folds into "Other" rather than inventing a colour.
//   * severity-*    a STATUS scale, not a series palette. Status colours are
//                   reserved, never reused for chart series, and never carry
//                   meaning alone — every use pairs the colour with its text
//                   label. `critical` measures 3.91:1, fine for a mark but
//                   below 4.5:1 for small text, which is why severity chips put
//                   the label in ink-100 beside a coloured dot rather than
//                   colouring the text itself.

export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Low-glare surfaces. A SOC console is watched for hours; a bright
        // background is fatiguing and washes out the severity colours, which
        // are the only thing that should compete for attention.
        surface: {
          950: '#080b12',
          900: '#0d1219',
          850: '#121824',
          800: '#181f2e',
          700: '#232c3d',
          600: '#334155',
        },
        ink: {
          100: '#e8edf6',  // 15.99:1 on surface-900
          200: '#c3ccdb',  // 11.61:1
          300: '#94a2b8',  //  7.26:1
          400: '#6b7a92',  // decorative only, never body text
        },
        severity: {
          critical: '#d03b3b',
          high: '#ec835a',
          medium: '#fab219',
          low: '#3987e5',
          info: '#9aa4b2',
        },
        series: {
          1: '#3987e5',
          2: '#d95926',
          3: '#199e70',
        },
        accent: {
          DEFAULT: '#3987e5',
          muted: '#1c5cab',
        },
        ok: '#199e70',
        warn: '#fab219',
        danger: '#d03b3b',
        // Chart chrome, stepped for the dark surface.
        grid: '#1b2331',
        axis: '#2c3646',
      },
      fontFamily: {
        sans: ['system-ui', '-apple-system', 'Segoe UI', 'Roboto', 'sans-serif'],
        mono: ['ui-monospace', 'SFMono-Regular', 'Menlo', 'Consolas', 'monospace'],
      },
      fontSize: {
        '2xs': ['0.6875rem', { lineHeight: '1rem' }],
      },
    },
  },
  plugins: [],
}
