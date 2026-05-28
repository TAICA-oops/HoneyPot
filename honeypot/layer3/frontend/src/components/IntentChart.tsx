import { useEffect, useState } from 'react'
import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from 'recharts'

const COLORS = ['#60a5fa','#f87171','#fb923c','#facc15','#a78bfa','#94a3b8']

export default function IntentChart() {
  const [data, setData] = useState<{intent:string; count:number}[]>([])
  useEffect(() => {
    fetch('/api/stats/intents').then(r => r.json()).then(setData)
  }, [])
  return (
    <div className="bg-gray-900 rounded-lg p-4">
      <div className="text-gray-400 text-xs mb-3">INTENT DISTRIBUTION</div>
      <ResponsiveContainer width="100%" height={200}>
        <PieChart>
          <Pie data={data} dataKey="count" nameKey="intent" cx="50%" cy="50%" outerRadius={70}>
            {data.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
          </Pie>
          <Tooltip formatter={(v) => [v, 'count']} />
          <Legend />
        </PieChart>
      </ResponsiveContainer>
    </div>
  )
}
