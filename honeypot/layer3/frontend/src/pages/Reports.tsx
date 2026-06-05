import { useEffect, useState } from 'react'
import Markdown from 'react-markdown'
import remarkGfm from 'remark-gfm'

export default function Reports() {
  const [sessions, setSessions] = useState<any[]>([])
  const [report, setReport] = useState<string>('')
  const [generating, setGenerating] = useState(false)
  const [lang, setLang] = useState<'en' | 'zh'>('en')
  const [currentSession, setCurrentSession] = useState<string>('')

  useEffect(() => { fetch('/api/sessions').then(r => r.json()).then(setSessions) }, [])

  const loadReport = async (id: string, forceLang?: 'en' | 'zh') => {
    const useLang = forceLang ?? lang
    setCurrentSession(id)
    const { report } = await fetch(`/api/reports/${id}`).then(r => r.json())
    if (report) { setReport(report); return }
    setGenerating(true)
    const res = await fetch(`/api/reports/${id}/generate?lang=${useLang}`, { method: 'POST' })
    const data = await res.json()
    setReport(data.report || 'Generation failed.')
    setGenerating(false)
  }

  const regenerate = async (useLang: 'en' | 'zh') => {
    if (!currentSession) return
    setGenerating(true)
    setReport('')
    const res = await fetch(`/api/reports/${currentSession}/generate?lang=${useLang}`, { method: 'POST' })
    const data = await res.json()
    setReport(data.report || 'Generation failed.')
    setGenerating(false)
  }

  return (
    <div className="grid grid-cols-3 gap-4">
      <div className="bg-gray-900 rounded-lg p-4 col-span-1 overflow-y-auto max-h-[calc(100vh-7rem)]">
        <div className="text-gray-400 text-xs mb-3">SELECT SESSION</div>
        {sessions.map(s => (
          <button key={s.session_id} onClick={() => loadReport(s.session_id)}
            className="w-full text-left p-3 rounded mb-2 bg-gray-800 hover:bg-gray-700">
            <div className="text-sm font-mono text-white">{s.attacker_ip}</div>
            <div className="text-xs text-gray-400">{s.protocol?.toUpperCase()} · {s.threat_level}</div>
          </button>
        ))}
      </div>
      <div className="col-span-2 bg-gray-900 rounded-lg p-6 overflow-y-auto max-h-[calc(100vh-7rem)]">
        <div className="flex items-center gap-2 mb-4">
          <span className="text-gray-400 text-xs">Language:</span>
          {(['en', 'zh'] as const).map(l => (
            <button key={l} onClick={() => { setLang(l); if (currentSession) regenerate(l) }}
              className={`px-3 py-1 rounded text-xs font-mono ${lang === l ? 'bg-blue-600 text-white' : 'bg-gray-700 text-gray-300 hover:bg-gray-600'}`}>
              {l === 'en' ? 'EN' : '中文'}
            </button>
          ))}
          {currentSession && !generating && (
            <button onClick={() => regenerate(lang)}
              className="ml-auto px-3 py-1 rounded text-xs bg-gray-700 text-gray-300 hover:bg-gray-600">
              Regenerate
            </button>
          )}
        </div>
        {generating && <div className="text-yellow-400 animate-pulse">Generating report with LLM...</div>}
        {!report && !generating && <div className="text-gray-600">Select a session to view or generate its report.</div>}
        {report && (
          <div className="prose prose-invert max-w-none prose-headings:text-white prose-p:text-gray-300">
            <Markdown remarkPlugins={[remarkGfm]}>{report}</Markdown>
          </div>
        )}
      </div>
    </div>
  )
}
