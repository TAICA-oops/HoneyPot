import { useEffect, useState } from 'react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'

type Row = { hour: string; count: number }

function hourBucket(iso: string): number {
  return new Date(iso).getHours()
}

export default function TimelineHeatmap() {
  const [data, setData] = useState<{ hour: number; count: number }[]>([])

  useEffect(() => {
    fetch('/api/stats/timeline')
      .then(r => r.json())
      .then((rows: Row[]) => {
        const buckets = Array.from({ length: 24 }, (_, h) => ({ hour: h, count: 0 }))
        rows.forEach(r => { buckets[hourBucket(r.hour)].count += r.count })
        setData(buckets)
      })
  }, [])

  const maxCount = Math.max(...data.map(d => d.count), 1)

  const label = (h: number) => {
    if (h === 0) return '12a'
    if (h === 12) return '12p'
    return h < 12 ? `${h}a` : `${h - 12}p`
  }

  return (
    <div className="bg-gray-900 rounded-lg p-4 col-span-2">
      <div className="text-gray-400 text-xs mb-3">ATTACK TIMELINE — HOURLY HEATMAP (UTC)</div>

      {/* heatmap grid */}
      <div className="grid grid-cols-24 gap-0.5 mb-3" style={{ gridTemplateColumns: 'repeat(24, 1fr)' }}>
        {data.map(d => {
          const intensity = d.count / maxCount
          const bg = intensity === 0
            ? 'bg-gray-800'
            : intensity < 0.25  ? 'bg-blue-900'
            : intensity < 0.5   ? 'bg-blue-700'
            : intensity < 0.75  ? 'bg-blue-500'
            : 'bg-blue-300'
          return (
            <div
              key={d.hour}
              title={`${label(d.hour)}: ${d.count} attacks`}
              className={`${bg} rounded-sm cursor-default`}
              style={{ height: 28 }}
            />
          )
        })}
      </div>

      {/* hour labels — every 4 hours */}
      <div className="flex justify-between text-gray-600 text-xs px-0 mb-4">
        {[0, 4, 8, 12, 16, 20, 23].map(h => (
          <span key={h}>{label(h)}</span>
        ))}
      </div>

      {/* bar chart */}
      <ResponsiveContainer width="100%" height={120}>
        <BarChart data={data} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
          <XAxis dataKey="hour" tickFormatter={label} tick={{ fill: '#6b7280', fontSize: 10 }} interval={3} />
          <YAxis tick={{ fill: '#6b7280', fontSize: 10 }} allowDecimals={false} />
          <Tooltip
            formatter={(v: number) => [`${v} attacks`, 'Count']}
            labelFormatter={(h: number) => `Hour: ${label(h)}`}
            contentStyle={{ background: '#111827', border: '1px solid #374151', borderRadius: 6 }}
            labelStyle={{ color: '#9ca3af' }}
            itemStyle={{ color: '#60a5fa' }}
          />
          {data.map((d, i) => {
            const intensity = d.count / maxCount
            const fill = intensity === 0 ? '#1f2937'
              : intensity < 0.25  ? '#1e3a5f'
              : intensity < 0.5   ? '#1d4ed8'
              : intensity < 0.75  ? '#3b82f6'
              : '#93c5fd'
            return <Cell key={i} fill={fill} />
          })}
          <Bar dataKey="count" radius={[2, 2, 0, 0]}>
            {data.map((d, i) => {
              const intensity = d.count / maxCount
              const fill = intensity === 0 ? '#1f2937'
                : intensity < 0.25  ? '#1e3a5f'
                : intensity < 0.5   ? '#1d4ed8'
                : intensity < 0.75  ? '#3b82f6'
                : '#93c5fd'
              return <Cell key={i} fill={fill} />
            })}
          </Bar>
        </BarChart>
      </ResponsiveContainer>

      {/* legend */}
      <div className="flex items-center gap-2 mt-2 text-xs text-gray-500">
        <span>Low</span>
        {['bg-gray-800', 'bg-blue-900', 'bg-blue-700', 'bg-blue-500', 'bg-blue-300'].map(c => (
          <div key={c} className={`${c} w-5 h-3 rounded-sm`} />
        ))}
        <span>High</span>
      </div>
    </div>
  )
}
