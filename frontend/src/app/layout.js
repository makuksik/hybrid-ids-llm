import './globals.css'
import { Activity, ShieldAlert, Globe, Settings, Server } from 'lucide-react'

export const metadata = {
  title: 'Test IDS',
  description: 'Hybrydowy system detekcji anomalii sieciowych',
}

export default function RootLayout({ children }) {
  return (
    <html lang="pl">
      <body className="flex h-screen bg-gray-50 text-gray-900" suppressHydrationWarning>
        {/* Sidebar */}
        <aside className="w-64 bg-slate-900 text-white flex flex-col">
          <div className="p-4 flex items-center gap-3 border-b border-slate-800">
            <ShieldAlert className="text-red-500" size={28} />
            <h1 className="text-xl font-bold tracking-wider">Test</h1>
          </div>
          <nav className="flex-1 p-4 space-y-2">
            <a href="/" className="flex items-center gap-3 p-3 bg-blue-600/20 text-blue-400 rounded-lg transition-colors">
              <Activity size={20} />
              <span className="font-medium">Dashboard</span>
            </a>
            <a href="/alerts" className="flex items-center gap-3 p-3 hover:bg-slate-800 rounded-lg transition-colors">
              <ShieldAlert size={20} />
              <span>Alerty LLM</span>
            </a>
            <a href="/map" className="flex items-center gap-3 p-3 hover:bg-slate-800 rounded-lg transition-colors">
              <Globe size={20} />
              <span>Mapa GeoIP</span>
            </a>
            <a href="/system" className="flex items-center gap-3 p-3 hover:bg-slate-800 rounded-lg transition-colors">
              <Server size={20} />
              <span>Zarządzanie IDS</span>
            </a>
          </nav>
          <div className="p-4 border-t border-slate-800 text-sm text-slate-400">
            Status: <span className="text-green-400 font-medium">Sniffer Aktywny</span>
          </div>
        </aside>

        {/* Main Content */}
        <main className="flex-1 flex flex-col overflow-hidden">
          {/* Header */}
          <header className="h-16 bg-white border-b flex items-center justify-between px-6">
            <h2 className="text-xl font-semibold">Przegląd Sieci</h2>
            <div className="flex items-center gap-4">
              <button className="p-2 hover:bg-gray-100 rounded-full"><Settings size={20} /></button>
              <div className="w-8 h-8 bg-blue-600 rounded-full flex items-center justify-center text-white font-bold">A</div>
            </div>
          </header>
          
          {/* Page Content */}
          <div className="flex-1 overflow-auto p-6">
            {children}
          </div>
        </main>
      </body>
    </html>
  )
}