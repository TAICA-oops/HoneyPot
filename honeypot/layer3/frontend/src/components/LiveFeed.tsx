import { useEffect, useRef, useState, useCallback } from 'react'

interface Event { command: string; intent: string; session_id: string; timestamp: string }

const intentColor: Record<string, string> = {
  reconnaissance: 'text-blue-400',
  privilege_escalation: 'text-red-400',
  data_exfiltration: 'text-orange-400',
  persistence: 'text-yellow-400',
  lateral_movement: 'text-purple-400',
  credential_harvesting: 'text-pink-400',
  web_recon: 'text-cyan-400',
  injection_attempt: 'text-rose-500',
  unknown: 'text-gray-400',
}

export default function LiveFeed() {
  const [events, setEvents] = useState<Event[]>([])
  const [connected, setConnected] = useState(false)
  const bottom = useRef<HTMLDivElement>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const retryTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return
    const scheme = location.protocol === 'https:' ? 'wss' : 'ws'
    const ws = new WebSocket(`${scheme}://${location.host}/ws/live`)
    wsRef.current = ws

    ws.onopen = () => setConnected(true)
    ws.onmessage = (e) => {
      try {
        const ev = JSON.parse(e.data) as Event
        setEvents(prev => [...prev.slice(-49), ev])
      } catch {}
    }
    ws.onclose = () => {
      setConnected(false)
      retryTimer.current = setTimeout(connect, 5000)
    }
    ws.onerror = () => ws.close()
  }, [])

  useEffect(() => {
    connect()
    return () => {
      if (retryTimer.current) clearTimeout(retryTimer.current)
      wsRef.current?.close()
    }
  }, [connect])

  useEffect(() => { bottom.current?.scrollIntoView({ behavior: 'smooth' }) }, [events])

  return (
    <div className="bg-gray-900 rounded-lg p-4 h-72 overflow-y-auto font-mono text-sm">
      <div className="flex items-center gap-2 text-xs mb-2">
        <span className={connected ? 'text-green-400' : 'text-yellow-400'}>
          {connected ? '● LIVE' : '○ RECONNECTING...'}
        </span>
      </div>
      {events.length === 0 && <div className="text-gray-600">Waiting for attackers...</div>}
      {events.map((ev, i) => (
        <div key={i} className="flex gap-3 mb-1">
          <span className="text-gray-600 shrink-0">{ev.timestamp?.slice(11, 19)}</span>
          <span className={`shrink-0 w-36 ${intentColor[ev.intent] ?? 'text-gray-400'}`}>{ev.intent}</span>
          <span className="text-green-300 truncate">{ev.command}</span>
        </div>
      ))}
      <div ref={bottom} />
    </div>
  )
}
