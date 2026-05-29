import { useEffect, useState } from 'react'
import LiveFeed from '../components/LiveFeed'
import IntentChart from '../components/IntentChart'
import CommandChart from '../components/CommandChart'
import TimelineHeatmap from '../components/TimelineHeatmap'
import GeoChart from '../components/GeoChart'

export default function Dashboard() {
  const [sessions, setSessions] = useState<any[]>([])
  useEffect(() => {
    const load = () => fetch('/api/sessions').then(r => r.json()).then(setSessions)
    load()
    const id = setInterval(load, 5000)
    return () => clearInterval(id)
  }, [])

  const threatBadge: Record<string, string> = {
    High: 'bg-red-900 text-red-300',
    Medium: 'bg-yellow-900 text-yellow-300',
    Low: 'bg-green-900 text-green-300',
    Critical: 'bg-red-950 text-red-200',
  }

  const critical  = sessions.filter(s => s.threat_level === 'Critical').length
  const high      = sessions.filter(s => s.threat_level === 'High').length
  const totalCmds = sessions.reduce((sum, s) => sum + (s.total_cmds || 0), 0)
  const uniqueIPs = new Set(sessions.map(s => s.attacker_ip)).size

  return (
    <div className="space-y-6">
      {/* stat cards */}
      <div className="grid grid-cols-4 gap-4">
        <div className="bg-gray-900 rounded-lg p-4">
          <div className="text-gray-400 text-xs">TOTAL SESSIONS</div>
          <div className="text-3xl font-bold text-white mt-1">{sessions.length}</div>
        </div>
        <div className="bg-gray-900 rounded-lg p-4">
          <div className="text-gray-400 text-xs">CRITICAL / HIGH</div>
          <div className="text-3xl font-bold text-red-400 mt-1">
            {critical > 0 && <span className="text-red-200 mr-1">{critical}⚡</span>}
            {high}
          </div>
        </div>
        <div className="bg-gray-900 rounded-lg p-4">
          <div className="text-gray-400 text-xs">TOTAL COMMANDS</div>
          <div className="text-3xl font-bold text-blue-400 mt-1">{totalCmds}</div>
        </div>
        <div className="bg-gray-900 rounded-lg p-4">
          <div className="text-gray-400 text-xs">UNIQUE SOURCE IPs</div>
          <div className="text-3xl font-bold text-purple-400 mt-1">{uniqueIPs}</div>
        </div>
      </div>

      {/* live feed */}
      <LiveFeed />

      {/* intent + command charts + recent sessions */}
      <div className="grid grid-cols-3 gap-4">
        <IntentChart />
        <CommandChart />
        <div className="bg-gray-900 rounded-lg p-4">
          <div className="text-gray-400 text-xs mb-3">RECENT SESSIONS</div>
          <div className="space-y-2">
            {sessions.slice(0, 8).map(s => (
              <div key={s.session_id} className="flex justify-between items-center text-sm">
                <span className="text-gray-300 font-mono text-xs">{s.attacker_ip}</span>
                <span className="text-gray-500 text-xs">{s.protocol?.toUpperCase()}</span>
                <span className={`text-xs px-2 py-0.5 rounded ${threatBadge[s.threat_level] ?? 'bg-gray-800 text-gray-400'}`}>
                  {s.threat_level ?? 'Unknown'}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* timeline heatmap + geo chart */}
      <div className="grid grid-cols-3 gap-4">
        <TimelineHeatmap />
        <GeoChart />
      </div>
    </div>
  )
}
