import { useEffect, useState } from 'react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'

type GeoRow = {
  ip: string
  country: string
  country_code: string
  city: string
  lat: number
  lon: number
  sessions: number
}

const FLAG_BASE = 'https://flagcdn.com/16x12/'

function countryFlag(code: string) {
  if (code === 'LO' || code === '??') return '🌐'
  return null
}

const COLORS = ['#ef4444', '#f97316', '#eab308', '#22c55e', '#3b82f6', '#8b5cf6', '#ec4899']

export default function GeoChart() {
  const [rows, setRows] = useState<GeoRow[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetch('/api/stats/geo')
      .then(r => r.json())
      .then((d: GeoRow[]) => { setRows(d); setLoading(false) })
      .catch(() => setLoading(false))
  }, [])

  // aggregate by country for the chart
  const byCountry = Object.values(
    rows.reduce<Record<string, { country: string; country_code: string; sessions: number }>>(
      (acc, r) => {
        const key = r.country
        if (!acc[key]) acc[key] = { country: r.country, country_code: r.country_code, sessions: 0 }
        acc[key].sessions += r.sessions
        return acc
      }, {}
    )
  ).sort((a, b) => b.sessions - a.sessions).slice(0, 7)

  return (
    <div className="bg-gray-900 rounded-lg p-4">
      <div className="text-gray-400 text-xs mb-3">ATTACK SOURCE — GEO DISTRIBUTION</div>

      {loading ? (
        <div className="text-gray-600 text-sm">Loading…</div>
      ) : rows.length === 0 ? (
        <div className="text-gray-600 text-sm">No session data yet</div>
      ) : (
        <>
          {/* bar chart */}
          <ResponsiveContainer width="100%" height={150}>
            <BarChart data={byCountry} layout="vertical" margin={{ top: 0, right: 8, left: 8, bottom: 0 }}>
              <XAxis type="number" tick={{ fill: '#6b7280', fontSize: 10 }} allowDecimals={false} />
              <YAxis type="category" dataKey="country" tick={{ fill: '#9ca3af', fontSize: 10 }} width={90} />
              <Tooltip
                formatter={(v: number) => [`${v} sessions`, 'Sessions']}
                contentStyle={{ background: '#111827', border: '1px solid #374151', borderRadius: 6 }}
                labelStyle={{ color: '#9ca3af' }}
                itemStyle={{ color: '#f87171' }}
              />
              <Bar dataKey="sessions" radius={[0, 3, 3, 0]}>
                {byCountry.map((_, i) => (
                  <Cell key={i} fill={COLORS[i % COLORS.length]} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>

          {/* IP table */}
          <div className="mt-3 space-y-1 max-h-40 overflow-y-auto">
            {rows.map(r => (
              <div key={r.ip} className="flex items-center justify-between text-xs text-gray-400 hover:bg-gray-800 px-1 rounded">
                <div className="flex items-center gap-2 min-w-0">
                  {countryFlag(r.country_code) ? (
                    <span>{countryFlag(r.country_code)}</span>
                  ) : (
                    <img
                      src={`${FLAG_BASE}${r.country_code.toLowerCase()}.png`}
                      alt={r.country_code}
                      className="w-4 h-3 object-cover rounded-sm"
                      onError={(e) => { (e.target as HTMLImageElement).style.display = 'none' }}
                    />
                  )}
                  <span className="font-mono text-gray-300">{r.ip}</span>
                  <span className="text-gray-600 truncate">{r.city ? `${r.city}, ` : ''}{r.country}</span>
                </div>
                <span className="text-red-400 font-mono ml-2 shrink-0">{r.sessions}s</span>
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  )
}
