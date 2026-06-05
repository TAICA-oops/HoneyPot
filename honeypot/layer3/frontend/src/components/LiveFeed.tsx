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

const MAX_FAIL = 3      // WebSocket 連失敗幾次後切換成 polling
const POLL_MS  = 3000  // polling 間隔

export default function LiveFeed() {
  const [events, setEvents]     = useState<Event[]>([])
  const [connected, setConnected] = useState(false)
  const [mode, setMode]         = useState<'ws' | 'polling'>('ws')
  const bottom   = useRef<HTMLDivElement>(null)
  const wsRef    = useRef<WebSocket | null>(null)
  const timer    = useRef<ReturnType<typeof setTimeout> | null>(null)
  const failCount = useRef(0)
  const seenIds  = useRef<Set<string>>(new Set())

  // ── polling fallback ──────────────────────────────────────────────────────
  const startPolling = useCallback(() => {
    setMode('polling')
    const poll = async () => {
      try {
        const cmds = await fetch('/api/stats/recent?limit=50').then(r => r.json()) as any[]
        const newEvents: Event[] = cmds
          .filter((c: any) => !seenIds.current.has(String(c.id)))
          .map((c: any) => {
            seenIds.current.add(String(c.id))
            return { command: c.command, intent: c.intent, session_id: '', timestamp: c.timestamp ?? '' }
          })
        if (newEvents.length) setEvents(prev => [...prev.slice(-(50 - newEvents.length)), ...newEvents])
        setConnected(true)
      } catch {
        setConnected(false)
      }
      timer.current = setTimeout(poll, POLL_MS)
    }
    poll()
  }, [])

  // ── WebSocket ─────────────────────────────────────────────────────────────
  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return
    const scheme = location.protocol === 'https:' ? 'wss' : 'ws'
    const ws = new WebSocket(`${scheme}://${location.host}/ws/live`)
    wsRef.current = ws

    ws.onopen = () => { setConnected(true); failCount.current = 0 }
    ws.onmessage = (e) => {
      try {
        const ev = JSON.parse(e.data) as Event
        setEvents(prev => [...prev.slice(-49), ev])
      } catch {}
    }
    ws.onclose = () => {
      setConnected(false)
      failCount.current += 1
      if (failCount.current >= MAX_FAIL) {
        startPolling()   // WebSocket 連失敗 3 次 → 切換 polling
      } else {
        timer.current = setTimeout(connect, 3000)
      }
    }
    ws.onerror = () => ws.close()
  }, [startPolling])

  useEffect(() => {
    connect()
    return () => {
      if (timer.current) clearTimeout(timer.current)
      wsRef.current?.close()
    }
  }, [connect])

  useEffect(() => { bottom.current?.scrollIntoView({ behavior: 'smooth' }) }, [events])

  const statusLabel = connected
    ? (mode === 'ws' ? '● LIVE' : '● POLLING')
    : (mode === 'ws' ? '○ RECONNECTING...' : '○ OFFLINE')
  const statusColor = connected ? 'text-green-400' : 'text-yellow-400'

  return (
    <div className="bg-gray-900 rounded-lg p-4 h-72 overflow-y-auto font-mono text-sm">
      <div className="flex items-center gap-2 text-xs mb-2">
        <span className={statusColor}>{statusLabel}</span>
        {mode === 'polling' && <span className="text-gray-600">(WebSocket unavailable, polling every {POLL_MS/1000}s)</span>}
      </div>
      {events.length === 0 && <div className="text-gray-600">Waiting for attackers...</div>}
      {events.map((ev, i) => (
        <div key={i} className="flex gap-3 mb-1">
          <span className="text-gray-600 shrink-0">{ev.timestamp?.slice(11, 19)}</span>
          <span className={`shrink-0 w-44 ${intentColor[ev.intent] ?? 'text-gray-400'}`}>{ev.intent}</span>
          <span className="text-green-300 truncate">{ev.command}</span>
        </div>
      ))}
      <div ref={bottom} />
    </div>
  )
}
