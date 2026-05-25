import { useEffect, useState } from 'react'

const intentColor: Record<string, string> = {
  reconnaissance: 'text-blue-400', privilege_escalation: 'text-red-400',
  data_exfiltration: 'text-orange-400', persistence: 'text-yellow-400',
  lateral_movement: 'text-purple-400', unknown: 'text-gray-500',
}

export default function Sessions() {
  const [sessions, setSessions] = useState<any[]>([])
  const [selected, setSelected] = useState<any>(null)

  useEffect(() => { fetch('/api/sessions').then(r => r.json()).then(setSessions) }, [])

  const loadSession = (id: string) =>
    fetch(`/api/sessions/${id}`).then(r => r.json()).then(setSelected)

  return (
    <div className="grid grid-cols-3 gap-4 h-[calc(100vh-7rem)]">
      <div className="bg-gray-900 rounded-lg p-4 overflow-y-auto col-span-1">
        <div className="text-gray-400 text-xs mb-3">SESSIONS</div>
        {sessions.map(s => (
          <button key={s.session_id} onClick={() => loadSession(s.session_id)}
            className="w-full text-left p-3 rounded mb-2 bg-gray-800 hover:bg-gray-700">
            <div className="text-sm font-mono text-white">{s.attacker_ip}</div>
            <div className="text-xs text-gray-400">{s.protocol?.toUpperCase()} · {s.total_cmds} cmds · {s.threat_level}</div>
          </button>
        ))}
      </div>
      <div className="bg-gray-900 rounded-lg p-4 overflow-y-auto col-span-2 font-mono text-sm">
        {!selected && <div className="text-gray-600">Select a session to replay</div>}
        {selected?.commands?.map((c: any, i: number) => (
          <div key={i} className="mb-2 border-b border-gray-800 pb-2">
            <div className="flex gap-3 text-xs text-gray-500 mb-1">
              <span>{c.timestamp?.slice(11, 19)}</span>
              <span className={intentColor[c.intent] ?? ''}>{c.intent}</span>
              {c.cache_hit ? <span className="text-gray-600">[cache]</span> : null}
            </div>
            <div className="text-green-300">$ {c.command}</div>
            <div className="text-gray-300 whitespace-pre-wrap text-xs mt-1">{c.response?.slice(0, 300)}</div>
          </div>
        ))}
      </div>
    </div>
  )
}
