"use client";
import { useState, useEffect } from 'react';
import { ShieldAlert, BrainCircuit, Zap, ShieldCheck, AlertCircle, Trash2, Filter } from 'lucide-react';

export default function LlmAlerts() {
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState({ high: 0, medium: 0, low: 0 });
  const [isMounted, setIsMounted] = useState(false);

  useEffect(() => {
    setIsMounted(true);
  }, []);

  // Funkcja symulująca analizę LLM na podstawie surowych danych ze sniffera
  const enrichWithLlm = (rawAlert) => {
    const isDns = rawAlert.proto === 'UDP' && rawAlert.port === 53;
    const isTcpHigh = rawAlert.proto === 'TCP' && rawAlert.port < 1024;

    if (isDns) {
      return {
        ...rawAlert,
        id: Date.now(),
        severity: 'HIGH',
        threat: 'Potencjalny DNS Amplification DDoS',
        confidence: 89,
        analysis: `Wykryto nienaturalny wolumen zapytań UDP na porcie 53 z adresu ${rawAlert.src}. Wzorzec odpowiada technice wzmocnienia DNS, zmierzającej do przeciążenia infrastruktury ofiary (${rawAlert.dst}).`,
        action: 'Zablokuj IP w Firewallu'
      };
    } else if (isTcpHigh) {
      return {
        ...rawAlert,
        id: Date.now(),
        severity: 'MEDIUM',
        threat: 'Skanowanie portów systemowych',
        confidence: 72,
        analysis: `Host ${rawAlert.src} próbuje nawiązać połączenia z portami niskiego numeru (well-known ports). Może to być próba mapowania usług systemowych (Reconnaissance).`,
        action: 'Obserwuj hosta'
      };
    } else {
      return {
        ...rawAlert,
        id: Date.now(),
        severity: 'LOW',
        threat: 'Nietypowy ruch TCP',
        confidence: 45,
        analysis: `Wykryto standardowy ruch na wysokim porcie (${rawAlert.port}). Poziom anomalii jest niski, ale host nie figurował wcześniej w bazie znanych urządzeń.`,
        action: 'Zignoruj'
      };
    }
  };

  useEffect(() => {
    if (!isMounted) return;

    const eventSource = new EventSource('http://localhost:8000/alerts/stream');

    eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'alert') {
          const enriched = enrichWithLlm(data);
          setAlerts((prev) => [enriched, ...prev].slice(0, 20));

          setStats(prev => ({
            ...prev,
            high: enriched.severity === 'HIGH' ? prev.high + 1 : prev.high,
            medium: enriched.severity === 'MEDIUM' ? prev.medium + 1 : prev.medium,
            low: enriched.severity === 'LOW' ? prev.low + 1 : prev.low,
          }));
        }
      } catch (err) {
        console.error("Błąd strumienia:", err);
      }
    };

    return () => eventSource.close();
  }, [isMounted]);

  if (!isMounted) return <div className="p-10">Inicjalizacja modułu LLM...</div>;

  return (
    <div className="max-w-6xl mx-auto space-y-6">
      {/* Statystyki Analizy */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <SeverityCard label="Wysokie Zagrożenie" count={stats.high} color="bg-red-500" icon={<AlertCircle />} />
        <SeverityCard label="Średnie Ryzyko" count={stats.medium} color="bg-amber-500" icon={<Zap />} />
        <SeverityCard label="Informacyjne" count={stats.low} color="bg-blue-500" icon={<BrainCircuit />} />
      </div>

      {/* Narzędzia i Filtry */}
      <div className="bg-white p-4 rounded-xl border flex items-center justify-between">
        <div className="flex gap-4">
          <button className="flex items-center gap-2 px-3 py-1.5 border rounded-lg text-sm hover:bg-gray-50">
            <Filter size={16} /> Filtruj
          </button>
          <button onClick={() => setAlerts([])} className="flex items-center gap-2 px-3 py-1.5 border rounded-lg text-sm text-red-600 hover:bg-red-50">
            <Trash2 size={16} /> Wyczyść historię
          </button>
        </div>
        <div className="text-sm text-gray-500">
          Status modelu: <span className="text-green-600 font-bold">GPT-4-IDS ONLINE</span>
        </div>
      </div>

      {/* Lista Alertów */}
      <div className="space-y-4">
        {alerts.length === 0 ? (
          <div className="bg-white p-20 rounded-xl border text-center text-gray-400">
            <BrainCircuit size={48} className="mx-auto mb-4 opacity-20" />
            Oczekiwanie na dane do analizy przez LLM...
          </div>
        ) : (
          alerts.map((alert) => (
            <div key={alert.id} className={`bg-white rounded-xl border shadow-sm overflow-hidden border-l-4 ${
              alert.severity === 'HIGH' ? 'border-l-red-500' :
              alert.severity === 'MEDIUM' ? 'border-l-amber-500' : 'border-l-blue-500'
            }`}>
              <div className="p-5">
                <div className="flex justify-between items-start mb-4">
                  <div className="flex items-center gap-3">
                    <div className={`p-2 rounded-lg ${
                      alert.severity === 'HIGH' ? 'bg-red-50 text-red-600' :
                      alert.severity === 'MEDIUM' ? 'bg-amber-50 text-amber-600' : 'bg-blue-50 text-blue-600'
                    }`}>
                      <ShieldAlert size={20} />
                    </div>
                    <div>
                      <h3 className="font-bold text-lg">{alert.threat}</h3>
                      <p className="text-sm text-gray-500 font-mono">
                        Źródło: {alert.src} &rarr; Cel: {alert.dst} [{alert.proto}:{alert.port}]
                      </p>
                    </div>
                  </div>
                  <div className="text-right">
                    <div className="text-xs font-bold uppercase tracking-wider text-gray-400 mb-1">Pewność modelu</div>
                    <div className="text-2xl font-black text-slate-800">{alert.confidence}%</div>
                  </div>
                </div>

                <div className="bg-slate-50 p-4 rounded-lg text-sm text-slate-700 leading-relaxed border italic mb-4">
                  <strong>Analiza LLM:</strong> {alert.analysis}
                </div>

                <div className="flex justify-end gap-3">
                  <button className="px-4 py-2 text-sm font-medium text-gray-600 hover:bg-gray-100 rounded-lg">Szczegóły pakietu</button>
                  <button className={`px-4 py-2 text-sm font-bold text-white rounded-lg transition-colors ${
                    alert.severity === 'HIGH' ? 'bg-red-600 hover:bg-red-700' : 'bg-slate-800 hover:bg-slate-900'
                  }`}>
                    {alert.action}
                  </button>
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

function SeverityCard({ label, count, color, icon }) {
  return (
    <div className="bg-white p-6 rounded-xl border shadow-sm flex items-center gap-4">
      <div className={`p-3 rounded-xl text-white ${color}`}>
        {icon}
      </div>
      <div>
        <p className="text-sm text-gray-500">{label}</p>
        <p className="text-2xl font-bold">{count}</p>
      </div>
    </div>
  );
}