import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom'
import Dashboard from './pages/Dashboard'
import Sessions from './pages/Sessions'
import Reports from './pages/Reports'

export default function App() {
  return (
    <BrowserRouter>
      <div className="min-h-screen bg-gray-950 text-gray-100">
        <nav className="bg-gray-900 border-b border-gray-800 px-6 py-3 flex gap-6">
          <span className="font-bold text-red-400 mr-4">🍯 HoneyPot</span>
          {[['/', 'Dashboard'], ['/sessions', 'Sessions'], ['/reports', 'Reports']].map(([to, label]) => (
            <NavLink key={to} to={to} end
              className={({ isActive }) => isActive ? 'text-white font-semibold' : 'text-gray-400 hover:text-white'}>
              {label}
            </NavLink>
          ))}
        </nav>
        <main className="p-6">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/sessions" element={<Sessions />} />
            <Route path="/reports" element={<Reports />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  )
}
