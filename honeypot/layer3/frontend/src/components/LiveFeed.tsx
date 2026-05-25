import { useEffect, useRef, useState } from 'react'

interface Event { command: string; intent: string; session_id: string; timestamp: string }

export default function LiveFeed() {
  const [events, setEvents] = useState<Event[]>([])
  const bottom = useRef<HTMLDivElement>(null)

  useEffect(() => {
    const ws = new WebSocket(`ws://${location.host}/ws/live`)
    ws.onmessage = (e) => {
      try {
        const ev = JSON.parse(e.data)
        setEvents(prev => [...prev.slice(-49), ev])
      } catch {}
    }
    return () => ws.close()
  }, [])

  useEffect(() => { bottom.current?.scrollIntoView({ behavior: 'smooth' }) }, [events])

  const intentColor: Record<string, string> = {
    reconnaissance: 'text-blue-400',
    privilege_escalation: 'text-red-400',
    data_exfiltration: 'text-orange-400',
    persistence: 'text-yellow-400',
    lateral_movement: 'text-purple-400',
    unknown: 'text-gray-400',
  }

  return (
    <div className="bg-gray-900 rounded-lg p-4 h-72 overflow-y-auto font-mono text-sm">
      <div className="text-gray-500 text-xs mb-2">● LIVE FEED</div>
      {events.length === 0 && <div className="text-gray-600">Waiting for attackers...</div>}
      {events.map((ev, i) => (
        <div key={i} className="flex gap-3 mb-1">
          <span className="text-gray-600 shrink-0">{ev.timestamp?.slice(11, 19)}</span>
          <span className={`shrink-0 w-32 ${intentColor[ev.intent] ?? 'text-gray-400'}`}>{ev.intent}</span>
          <span className="text-green-300 truncate">{ev.command}</span>
        </div>
      ))}
      <div ref={bottom} />
    </div>
  )
}
