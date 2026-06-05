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

  const loadReport = async (id: string) => {
    setCurrentSession(id)
    setReport('')
    setGenerating(false)
    const { report: existing } = await fetch(`/api/reports/${id}`).then(r => r.json())
    if (existing) { setReport(existing); return }
    setGenerating(true)
    const res = await fetch(`/api/reports/${id}/generate?lang=${lang}`, { method: 'POST' })
    const data = await res.json()
    setReport(data.report || 'Generation failed.')
    setGenerating(false)
  }

  const regenerate = async (useLang: 'en' | 'zh') => {
    if (!currentSession) return
    setReport('')
    setGenerating(true)
    // save=false: 切換語言只顯示，不覆蓋 DB 裡的原始報告
    const res = await fetch(`/api/reports/${currentSession}/generate?lang=${useLang}&save=false`, { method: 'POST' })
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
            className={`w-full text-left p-3 rounded mb-2 hover:bg-gray-700 ${currentSession === s.session_id ? 'bg-gray-700' : 'bg-gray-800'}`}>
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
        {generating && <div className="text-yellow-400 animate-pulse mb-4">Generating report with LLM...</div>}
        {!report && !generating && <div className="text-gray-600">Select a session to view or generate its report.</div>}
        {report && !generating && (
          <div className="text-gray-300 text-sm
            [&_h2]:text-white [&_h2]:text-base [&_h2]:font-bold [&_h2]:mt-5 [&_h2]:mb-2 [&_h2]:border-b [&_h2]:border-gray-700 [&_h2]:pb-1
            [&_h3]:text-gray-200 [&_h3]:font-semibold [&_h3]:mt-3 [&_h3]:mb-1
            [&_p]:mb-2 [&_p]:leading-relaxed
            [&_ul]:list-disc [&_ul]:ml-5 [&_ul]:mb-2 [&_li]:mb-1
            [&_strong]:text-white
            [&_table]:w-full [&_table]:border-collapse [&_table]:my-3 [&_table]:text-xs
            [&_th]:border [&_th]:border-gray-600 [&_th]:bg-gray-800 [&_th]:px-3 [&_th]:py-2 [&_th]:text-left [&_th]:text-gray-200
            [&_td]:border [&_td]:border-gray-700 [&_td]:px-3 [&_td]:py-1.5 [&_td]:align-top
            [&_code]:bg-gray-800 [&_code]:px-1 [&_code]:rounded [&_code]:text-green-300 [&_code]:text-xs">
            <Markdown remarkPlugins={[remarkGfm]}>{report}</Markdown>
          </div>
        )}
      </div>
    </div>
  )
}
