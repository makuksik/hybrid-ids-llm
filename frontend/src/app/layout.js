"use client";
import './globals.css'
import { Activity, ShieldAlert, Globe, Settings, Server } from 'lucide-react'
import Link from 'next/link'
import { usePathname } from 'next/navigation'

export default function RootLayout({ children }) {
  const pathname = usePathname();

  // Funkcja pomocnicza do nadawania stylów aktywnym linkom
  const getLinkStyle = (path) => {
    const baseStyle = "flex items-center gap-3 p-3 rounded-lg transition-colors";
    const activeStyle = "bg-blue-600/20 text-blue-400 font-medium";
    const inactiveStyle = "hover:bg-slate-800 text-slate-300";

    return `${baseStyle} ${pathname === path ? activeStyle : inactiveStyle}`;
  };

  return (
    <html lang="pl">
      <body className="flex h-screen bg-gray-50 text-gray-900" suppressHydrationWarning>
        {/* Sidebar */}
        <aside className="w-64 bg-slate-900 text-white flex flex-col">
          <div className="p-4 flex items-center gap-3 border-b border-slate-800">
            <ShieldAlert className="text-red-500" size={28} />
            <h1 className="text-xl font-bold tracking-wider">Test IDS</h1>
          </div>

          <nav className="flex-1 p-4 space-y-2">
            <Link href="/" className={getLinkStyle('/')}>
              <Activity size={20} />
              <span>Dashboard</span>
            </Link>

            <Link href="/alerts" className={getLinkStyle('/alerts')}>
              <ShieldAlert size={20} />
              <span>Alerty LLM</span>
            </Link>

            <Link href="/map" className={getLinkStyle('/map')}>
              <Globe size={20} />
              <span>Mapa GeoIP</span>
            </Link>

            <Link href="/system" className={getLinkStyle('/system')}>
              <Server size={20} />
              <span>Zarządzanie IDS</span>
            </Link>
          </nav>

          <div className="p-4 border-t border-slate-800 text-sm text-slate-400">
            Status: <span className="text-green-400 font-medium">Sniffer Aktywny</span>
          </div>
        </aside>

        {/* Main Content */}
        <main className="flex-1 flex flex-col overflow-hidden">
          <header className="h-16 bg-white border-b flex items-center justify-between px-6">
            <h2 className="text-xl font-semibold">
              {pathname === '/' && "Przegląd Sieci"}
              {pathname === '/map' && "Lokalizacja Zagrożeń"}
              {pathname === '/alerts' && "Analiza AI"}
            </h2>
            <div className="flex items-center gap-4">
              <button className="p-2 hover:bg-gray-100 rounded-full"><Settings size={20} /></button>
              <div className="w-8 h-8 bg-blue-600 rounded-full flex items-center justify-center text-white font-bold">A</div>
            </div>
          </header>

          <div className="flex-1 overflow-auto p-6">
            {children}
          </div>
        </main>
      </body>
    </html>
  )
}