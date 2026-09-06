/**
 * Chart components.
 *
 * Colour choices here are validated, not chosen by eye. An earlier hand-picked
 * severity ramp failed a colour-vision-deficiency check on this surface (two
 * hues outside the lightness band, one below the chroma floor, and an adjacent
 * pair only 10.2 ΔE apart in normal vision). The values now in the Tailwind
 * config passed the same checks.
 *
 * Rules applied throughout:
 *   - one y-axis, never two (a dual-axis chart invents correlations)
 *   - categorical series capped at three validated hues; a fourth folds to
 *     "Other" rather than inventing a colour
 *   - every multi-series chart carries a legend AND a second visual channel
 *     (line dash, direct label), so identity is never colour-alone
 *   - grid and axes recede; the data is the only thing with contrast
 */

import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'

import { formatNumber, formatShortTime, titleCase } from '@/lib/format'
import type { AuthTrendPoint, Severity, TimeSeriesPoint } from '@/types/api'

const AXIS = '#6b7a92'
const GRID = '#1b2331'
const SURFACE = '#121824'

const SERIES = ['#3987e5', '#d95926', '#199e70'] as const

export const SEVERITY_COLOR: Record<Severity, string> = {
  critical: '#d03b3b',
  high: '#ec835a',
  medium: '#fab219',
  low: '#3987e5',
  info: '#9aa4b2',
}

const axisProps = {
  stroke: AXIS,
  tick: { fill: AXIS, fontSize: 10 },
  tickLine: false,
  axisLine: { stroke: '#2c3646' },
}

function TooltipBox({
  active,
  payload,
  label,
  labelFormatter,
}: {
  active?: boolean
  payload?: { name?: string; value?: number | string; color?: string; dataKey?: string }[]
  label?: string
  labelFormatter?: (value: string) => string
}) {
  if (!active || !payload?.length) return null
  return (
    <div className="rounded border border-surface-700 bg-surface-850 px-2.5 py-2 shadow-lg">
      {label !== undefined ? (
        <p className="text-2xs text-ink-300 mb-1">
          {labelFormatter ? labelFormatter(String(label)) : label}
        </p>
      ) : null}
      {payload.map((entry) => (
        <p key={entry.dataKey ?? entry.name} className="flex items-center gap-1.5 text-2xs">
          <span
            aria-hidden
            className="h-1.5 w-1.5 rounded-full"
            style={{ background: entry.color }}
          />
          <span className="text-ink-300">{titleCase(String(entry.name ?? ''))}</span>
          <span className="text-ink-100 tabular ml-auto pl-3">
            {typeof entry.value === 'number' ? formatNumber(entry.value) : entry.value}
          </span>
        </p>
      ))}
    </div>
  )
}

export function ChartFrame({
  height = 200,
  children,
}: {
  height?: number
  children: React.ReactElement
}) {
  return (
    <div style={{ height }} className="w-full">
      <ResponsiveContainer width="100%" height="100%">
        {children}
      </ResponsiveContainer>
    </div>
  )
}

/** Single-series volume over time. One series, so no legend: the title names it. */
export function VolumeArea({
  data,
  color = SERIES[0],
  height = 180,
}: {
  data: TimeSeriesPoint[]
  color?: string
  height?: number
}) {
  const gradientId = `grad-${color.replace('#', '')}`
  return (
    <ChartFrame height={height}>
      <AreaChart data={data} margin={{ top: 8, right: 12, bottom: 0, left: -8 }}>
        <defs>
          <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={color} stopOpacity={0.35} />
            <stop offset="100%" stopColor={color} stopOpacity={0.02} />
          </linearGradient>
        </defs>
        <CartesianGrid stroke={GRID} vertical={false} />
        <XAxis dataKey="bucket" tickFormatter={formatShortTime} minTickGap={40} {...axisProps} />
        <YAxis width={44} allowDecimals={false} {...axisProps} />
        <Tooltip
          content={<TooltipBox labelFormatter={formatShortTime} />}
          cursor={{ stroke: AXIS, strokeDasharray: '3 3' }}
        />
        <Area
          type="monotone"
          dataKey="count"
          name="Events"
          stroke={color}
          strokeWidth={2}
          fill={`url(#${gradientId})`}
          dot={false}
          activeDot={{ r: 4, strokeWidth: 2, stroke: SURFACE }}
        />
      </AreaChart>
    </ChartFrame>
  )
}

/**
 * Authentication success vs failure.
 *
 * Two series whose colours sit in the CVD "warn" band, which is permitted only
 * with a second encoding channel — so failure is dashed and success is solid,
 * and both are named in the legend. A viewer who cannot separate the hues can
 * still separate the lines.
 */
export function AuthTrendChart({ data, height = 200 }: { data: AuthTrendPoint[]; height?: number }) {
  return (
    <ChartFrame height={height}>
      <LineChart data={data} margin={{ top: 8, right: 12, bottom: 0, left: -8 }}>
        <CartesianGrid stroke={GRID} vertical={false} />
        <XAxis dataKey="bucket" tickFormatter={formatShortTime} minTickGap={40} {...axisProps} />
        <YAxis width={44} allowDecimals={false} {...axisProps} />
        <Tooltip
          content={<TooltipBox labelFormatter={formatShortTime} />}
          cursor={{ stroke: AXIS, strokeDasharray: '3 3' }}
        />
        <Legend
          wrapperStyle={{ fontSize: 11, color: AXIS, paddingTop: 4 }}
          iconType="plainline"
          iconSize={14}
        />
        <Line
          type="monotone"
          dataKey="success"
          name="Successful"
          stroke="#199e70"
          strokeWidth={2}
          dot={false}
          activeDot={{ r: 4 }}
        />
        <Line
          type="monotone"
          dataKey="failure"
          name="Failed"
          stroke="#d03b3b"
          strokeWidth={2}
          // The second channel: dash pattern carries identity when hue cannot.
          strokeDasharray="5 3"
          dot={false}
          activeDot={{ r: 4 }}
        />
      </LineChart>
    </ChartFrame>
  )
}

/**
 * Severity distribution.
 *
 * Severity is an ordered status scale, so every bar is direct-labelled with the
 * severity name. The colour reinforces the label; it never replaces it.
 */
export function SeverityBars({
  data,
  height = 180,
}: {
  data: { severity: Severity; count: number }[]
  height?: number
}) {
  return (
    <ChartFrame height={height}>
      <BarChart data={data} layout="vertical" margin={{ top: 4, right: 28, bottom: 0, left: 4 }}>
        <CartesianGrid stroke={GRID} horizontal={false} />
        <XAxis type="number" allowDecimals={false} {...axisProps} />
        <YAxis
          type="category"
          dataKey="severity"
          width={70}
          tickFormatter={titleCase}
          {...axisProps}
        />
        <Tooltip content={<TooltipBox />} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
        <Bar dataKey="count" name="Alerts" radius={[0, 4, 4, 0]} barSize={16}>
          {data.map((entry) => (
            <Cell key={entry.severity} fill={SEVERITY_COLOR[entry.severity]} />
          ))}
        </Bar>
      </BarChart>
    </ChartFrame>
  )
}

/**
 * Horizontal ranking (top IPs, top rules, ATT&CK techniques).
 *
 * A single hue: these bars encode magnitude, not identity, so giving each row
 * its own colour would imply a categorical difference that does not exist.
 */
export function RankedBars<T extends object>({
  data,
  labelKey,
  valueKey,
  height = 220,
  color = SERIES[0],
}: {
  data: T[]
  // Constrained to the row type's own keys, so a typo in a call site is a
  // compile error rather than an empty chart at runtime.
  labelKey: Extract<keyof T, string>
  valueKey: Extract<keyof T, string>
  height?: number
  color?: string
}) {
  return (
    <ChartFrame height={height}>
      <BarChart data={data} layout="vertical" margin={{ top: 4, right: 28, bottom: 0, left: 4 }}>
        <CartesianGrid stroke={GRID} horizontal={false} />
        <XAxis type="number" allowDecimals={false} {...axisProps} />
        <YAxis
          type="category"
          dataKey={labelKey}
          width={150}
          tick={{ fill: AXIS, fontSize: 10 }}
          tickLine={false}
          axisLine={{ stroke: '#2c3646' }}
        />
        <Tooltip content={<TooltipBox />} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
        <Bar dataKey={valueKey} name="Count" fill={color} radius={[0, 4, 4, 0]} barSize={14} />
      </BarChart>
    </ChartFrame>
  )
}

export { SERIES }
