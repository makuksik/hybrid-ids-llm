import { ArrowUpRight, ArrowDownRight, Activity, AlertTriangle, Globe } from 'lucide-react'

export default function Dashboard() {
  return (
    <div className="max-w-7xl mx-auto space-y-6">
      
      {/* Statystyki */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <StatCard title="Suma Pakietów" value="124,532" trend="+12%" icon={<Activity />} />
        <StatCard title="Ruch TCP" value="98,102" trend="+5%" icon={<ArrowUpRight className="text-green-500" />} />
        <StatCard title="Ruch UDP" value="26,430" trend="-2%" icon={<ArrowDownRight className="text-blue-500" />} />
        <StatCard title="Unikalne IP" value="1,402" trend="+18%" icon={<Globe />} isAlert={true} />
      </div>

      {/* Wizualizacja i Mapa */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 h-96">
        <div className="bg-white p-6 rounded-xl border shadow-sm col-span-2 flex flex-col">
          <h3 className="text-lg font-semibold mb-4">Wizualizacja Statystyk (Ruch w czasie)</h3>
          <div className="flex-1 bg-gray-50 rounded border border-dashed flex items-center justify-center text-gray-400">
            [ Tu wyląduje wykres Recharts ]
          </div>
        </div>

        <div className="bg-white p-6 rounded-xl border shadow-sm flex flex-col">
          <h3 className="text-lg font-semibold mb-4">Mapa Świata (GeoIP)</h3>
          <div className="flex-1 bg-blue-50 rounded border border-dashed border-blue-200 flex items-center justify-center text-blue-400">
            [ Integracja Mapy ]
          </div>
        </div>
      </div>

      {/* Live Feed i AI Alerts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white p-6 rounded-xl border shadow-sm">
          <h3 className="text-lg font-semibold mb-4">Live Traffic Feed</h3>
          <div className="space-y-3 font-mono text-sm">
            <div className="p-2 bg-gray-50 border rounded flex justify-between">
              <span>[TCP] 192.168.1.15 &rarr; 104.21.34.12</span>
              <span className="text-gray-500">Port: 443</span>
            </div>
            <div className="p-2 bg-gray-50 border rounded flex justify-between">
              <span>[UDP] 192.168.1.15 &rarr; 8.8.8.8</span>
              <span className="text-gray-500">Port: 53</span>
            </div>
            <div className="p-2 bg-red-50 text-red-700 border border-red-200 rounded flex justify-between">
              <span>[TCP] 112.45.67.89 &rarr; 192.168.1.100</span>
              <span className="font-bold">Port: 22 (SSH)</span>
            </div>
          </div>
        </div>

        <div className="bg-white p-6 rounded-xl border shadow-sm border-l-4 border-l-purple-500">
          <div className="flex items-center gap-2 mb-4">
            <AlertTriangle className="text-purple-500" />
            <h3 className="text-lg font-semibold">Ostatnia analiza LLM</h3>
          </div>
          <div className="bg-purple-50 text-purple-900 p-4 rounded-lg text-sm leading-relaxed">
            <strong>Analiza anomalii #4092:</strong> Wykryto nietypowy wzrost zapytań UDP na porcie 53 (DNS) z pojedynczego adresu IP. LLM klasyfikuje to zdarzenie jako potencjalną próbę <em>DNS Amplification DDoS</em> (Pewność: 87%). <br/><br/>
            <strong>Sugerowana akcja:</strong> Uruchomienie skryptu blokującego IP (Firewall script).
          </div>
          <button className="mt-4 w-full bg-slate-900 text-white py-2 rounded-lg hover:bg-slate-800 transition-colors">
            Zablokuj IP (Active Response)
          </button>
        </div>
      </div>
    </div>
  )
}

// Komponent StatCard w czystym JS
function StatCard({ title, value, trend, icon, isAlert = false }) {
  return (
    <div className={`bg-white p-6 rounded-xl border shadow-sm flex items-start justify-between ${isAlert ? 'border-red-200 bg-red-50/30' : ''}`}>
      <div>
        <p className="text-sm text-gray-500 mb-1">{title}</p>
        <h4 className="text-2xl font-bold">{value}</h4>
        <span className={`text-sm ${trend.startsWith('+') ? 'text-green-500' : 'text-red-500'}`}>
          {trend} od ostatniej godziny
        </span>
      </div>
      <div className="p-3 bg-gray-50 rounded-lg text-gray-600">
        {icon}
      </div>
    </div>
  )
}