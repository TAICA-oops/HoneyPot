import { useEffect, useState } from 'react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'

type CommandStat = { command: string; count: number }

export default function CommandChart() {
  const [data, setData] = useState<CommandStat[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetch('/api/stats/commands?limit=10')
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`)
        return r.json() as Promise<CommandStat[]>
      })
      .then(setData)
      .catch(() => setError('Failed to load'))
      .finally(() => setLoading(false))
  }, [])

  return (
    <div className="bg-gray-900 rounded-lg p-4">
      <div className="text-gray-400 text-xs mb-3">TOP COMMANDS</div>
      {loading && <div className="text-gray-600 text-sm">Loading...</div>}
      {error && <div className="text-red-500 text-sm">{error}</div>}
      {!loading && !error && data.length === 0 && (
        <div className="text-gray-600 text-sm">No commands yet</div>
      )}
      {!loading && !error && data.length > 0 && (
        <ResponsiveContainer width="100%" height={200}>
          <BarChart data={data} layout="vertical" margin={{ left: 16 }}>
            <XAxis type="number" stroke="#4b5563" tick={{ fontSize: 11 }} />
            <YAxis
              type="category"
              dataKey="command"
              stroke="#4b5563"
              tick={{ fontSize: 10, fill: '#9ca3af' }}
              width={140}
            />
            <Tooltip
              contentStyle={{ background: '#111827', border: '1px solid #374151' }}
              labelStyle={{ color: '#f3f4f6' }}
            />
            <Bar dataKey="count" fill="#3b82f6" radius={[0, 3, 3, 0]} />
          </BarChart>
        </ResponsiveContainer>
      )}
    </div>
  )
}
