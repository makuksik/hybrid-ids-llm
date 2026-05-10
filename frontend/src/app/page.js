"use client";
import { useState, useEffect } from 'react';
import { ComposableMap, Geographies, Geography, Marker, ZoomableGroup } from "react-simple-maps";
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, Legend } from 'recharts';
import { ArrowUpRight, ArrowDownRight, Activity, AlertTriangle, Globe, ShieldAlert, Navigation, MapPin, BrainCircuit, Zap, AlertCircle, Trash2, Filter, LayoutDashboard, Map as MapIcon } from 'lucide-react';

const geoUrl = "https://unpkg.com/world-atlas@2.0.2/countries-110m.json";

const prefixToGeo = {
  "8": { coords: [-95.71, 37.09], country: "USA" },
  "12": { coords: [10.45, 51.16], country: "Niemcy" },
  "17": { coords: [-3.43, 55.37], country: "Wielka Brytania" },
  "24": { coords: [2.21, 46.22], country: "Francja" },
  "45": { coords: [-51.92, -14.23], country: "Brazylia" },
  "50": { coords: [105.31, 61.52], country: "Rosja" },
  "72": { coords: [78.96, 20.59], country: "Indie" },
  "80": { coords: [104.19, 35.86], country: "Chiny" },
  "104": { coords: [133.28, -25.27], country: "Australia" },
  "142": { coords: [138.25, 36.20], country: "Japonia" },
  "185": { coords: [19.14, 51.91], country: "Polska" },
  "200": { coords: [22.93, -30.55], country: "RPA" },
  "212": { coords: [-106.34, 56.13], country: "Kanada" }
};

const resolveGeoMock = (ip) => {
  const parts = ip.split('.');
  if (parts.length !== 4) return [0, 0];
  const geoData = prefixToGeo[parts[0]];
  if (geoData) {
    const offsetX = (Math.random() - 0.5) * 4;
    const offsetY = (Math.random() - 0.5) * 4;
    return [geoData.coords[0] + offsetX, geoData.coords[1] + offsetY];
  }
  return [15.0 + (Math.random() * 5), 50.0 + (Math.random() * 5)];
};

const enrichWithLlm = (rawAlert) => {
  const isDns = rawAlert.proto === 'UDP' && rawAlert.port === 53;
  const isTcpHigh = rawAlert.proto === 'TCP' && rawAlert.port < 1024;
  const uniqueId = `${Date.now()}-${Math.random()}`;

  if (isDns) {
    return { ...rawAlert, id: uniqueId, severity: 'HIGH', threat: 'Potencjalny DNS Amplification DDoS', confidence: 89, analysis: `Wykryto nienaturalny wolumen zapytań UDP na porcie 53 z adresu ${rawAlert.src}. Wzorzec odpowiada technice wzmocnienia DNS, zmierzającej do przeciążenia infrastruktury ofiary (${rawAlert.dst}).`, action: 'Zablokuj IP w Firewallu' };
  } else if (isTcpHigh) {
    return { ...rawAlert, id: uniqueId, severity: 'MEDIUM', threat: 'Skanowanie portów systemowych', confidence: 72, analysis: `Host ${rawAlert.src} próbuje nawiązać połączenia z portami niskiego numeru (well-known ports). Może to być próba mapowania usług systemowych (Reconnaissance).`, action: 'Obserwuj hosta' };
  } else {
    return { ...rawAlert, id: uniqueId, severity: 'LOW', threat: 'Nietypowy ruch TCP', confidence: 45, analysis: `Wykryto standardowy ruch na wysokim porcie (${rawAlert.port}). Poziom anomalii jest niski, ale host nie figurował wcześniej w bazie znanych urządzeń.`, action: 'Zignoruj' };
  }
};

export default function AppBrain() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [isMounted, setIsMounted] = useState(false);

  const [stats, setStats] = useState({ total: 0, tcp: 0, udp: 0, uniqueIps: 0 });
  const [liveFeed, setLiveFeed] = useState([]);
  const [dataPPS, setDataPPS] = useState([]);

  const [markers, setMarkers] = useState([]);
  const [recentAlert, setRecentAlert] = useState(null);

  const [llmAlerts, setLlmAlerts] = useState([]);
  const [llmStats, setLlmStats] = useState({ high: 0, medium: 0, low: 0 });

  useEffect(() => {
    setIsMounted(true);
  }, []);

  useEffect(() => {
    if (!isMounted) return;

    const eventSource = new EventSource('http://localhost:8000/alerts/stream');

    eventSource.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);

        if (data.type === 'report') {
          setStats({ total: data.total, tcp: data.tcp, udp: data.udp, uniqueIps: data.unique_ips });
          setDataPPS((prev) => {
            const newPoint = { time: new Date().toLocaleTimeString('pl-PL', { minute: '2-digit', second: '2-digit' }), pps: data.pps || data.total };
            return [...prev, newPoint].slice(-15);
          });
        } else if (data.type === 'alert') {
          setLiveFeed((prev) => [data, ...prev].slice(0, 15));

          const coords = resolveGeoMock(data.dst);
          const newMarker = { id: `${data.src}-${Date.now()}-${Math.random()}`, ip: data.src, proto: data.proto, port: data.port, coordinates: coords };
          setRecentAlert(newMarker);
          setMarkers((prev) => [...prev, newMarker].slice(-30));

          const enriched = enrichWithLlm(data);
          setLlmAlerts((prev) => [enriched, ...prev].slice(0, 20));
          setLlmStats(prev => ({
            ...prev,
            high: enriched.severity === 'HIGH' ? prev.high + 1 : prev.high,
            medium: enriched.severity === 'MEDIUM' ? prev.medium + 1 : prev.medium,
            low: enriched.severity === 'LOW' ? prev.low + 1 : prev.low,
          }));
        }
      } catch (err) {
        console.error("Błąd parsowania:", err);
      }
    };

    eventSource.onerror = () => eventSource.close();
    return () => eventSource.close();
  }, [isMounted]);

  const handleBlockIp = async (ip) => {

  console.log("TEST KLIKNIĘCIA! Próba zablokowania IP:", ip);

    try {
      const response = await fetch('http://localhost:8000/block-ip', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ ip: ip })
      });

      const result = await response.json();

      if (result.status === 'success') {
        alert(result.message);
      } else {
        alert("Błąd: " + result.message);
      }
    } catch (error) {
      console.error("Błąd podczas wysyłania żądania blokady:", error);
      alert("Wystąpił błąd podczas próby zablokowania IP.");
    }
  };

  if (!isMounted) return <div className="min-h-screen bg-slate-50 flex items-center justify-center">Inicjalizacja Systemu NetSentinel...</div>;

  return (
    <div className="min-h-screen bg-slate-50 flex flex-col">
      <header className="bg-slate-900 text-white shadow-lg sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
          <div className="flex items-center gap-3 font-bold text-xl">
            <ShieldAlert className="text-blue-500" />
            <span>NetSentinel <span className="text-blue-500">IDS</span></span>
          </div>

          <nav className="flex gap-1 bg-slate-800 p-1 rounded-lg">
            <TabButton active={activeTab === 'dashboard'} onClick={() => setActiveTab('dashboard')} icon={<LayoutDashboard size={18} />} label="Statystyki" />
            <TabButton active={activeTab === 'map'} onClick={() => setActiveTab('map')} icon={<Globe size={18} />} label="Mapa Świata" />
            <TabButton active={activeTab === 'alerts'} onClick={() => setActiveTab('alerts')} icon={<BrainCircuit size={18} />} label="Analiza LLM" />
          </nav>
        </div>
      </header>

      <main className="flex-1 p-6">
        {activeTab === 'dashboard' && <DashboardView stats={stats} liveFeed={liveFeed} dataPPS={dataPPS} />}
        {activeTab === 'map' && <MapView markers={markers} recentAlert={recentAlert} />}
        {activeTab === 'alerts' && <AlertsView alerts={llmAlerts} stats={llmStats} clearAlerts={() => setLlmAlerts([])} onBlockIp={handleBlockIp} />}
      </main>
    </div>
  );
}

function TabButton({ active, onClick, icon, label }) {
  return (
    <button onClick={onClick} className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-colors ${active ? 'bg-blue-600 text-white shadow-sm' : 'text-slate-300 hover:text-white hover:bg-slate-700'}`}>
      {icon} {label}
    </button>
  );
}

function DashboardView({ stats, liveFeed, dataPPS }) {
  const dataProto = stats.total === 0
    ? [{ name: 'Brak', value: 1, color: '#e2e8f0' }]
    : [
        { name: 'TCP', value: stats.tcp, color: '#3b82f6' },
        { name: 'UDP', value: stats.udp, color: '#a855f7' },
        { name: 'Inne', value: Math.max(0, stats.total - stats.tcp - stats.udp), color: '#94a3b8' }
      ];

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <StatCard title="Suma Pakietów" value={stats.total.toLocaleString()} trend="Live" icon={<Activity />} />
        <StatCard title="Ruch TCP" value={stats.tcp.toLocaleString()} trend="Live" icon={<ArrowUpRight className="text-green-500" />} />
        <StatCard title="Ruch UDP" value={stats.udp.toLocaleString()} trend="Live" icon={<ArrowDownRight className="text-blue-500" />} />
        <StatCard title="Unikalne IP" value={stats.uniqueIps.toLocaleString()} trend="Live" icon={<Globe />} isAlert={true} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="bg-white p-6 rounded-xl border shadow-sm col-span-2 h-96 flex flex-col">
          <h3 className="text-lg font-semibold text-slate-800 mb-4">Natężenie ruchu (PPS)</h3>
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={dataPPS}><CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#f1f5f9" /><XAxis dataKey="time" tick={{fontSize: 12}} /><YAxis hide /><Tooltip /><Line type="monotone" dataKey="pps" stroke="#3b82f6" strokeWidth={3} dot={false} isAnimationActive={false} /></LineChart>
          </ResponsiveContainer>
        </div>
        <div className="bg-white p-6 rounded-xl border shadow-sm h-96 flex flex-col">
          <h3 className="text-lg font-semibold text-slate-800 mb-4">Podział Protokołów</h3>
          <ResponsiveContainer width="100%" height="100%">
            <PieChart><Pie data={dataProto} innerRadius={60} outerRadius={80} paddingAngle={5} dataKey="value" isAnimationActive={false}>{dataProto.map((entry, index) => <Cell key={`cell-${index}`} fill={entry.color} />)}</Pie><Tooltip /><Legend verticalAlign="bottom" height={36} iconType="circle" /></PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="bg-white p-6 rounded-xl border shadow-sm flex flex-col h-64">
        <h3 className="text-lg font-semibold text-slate-800 mb-4 flex items-center gap-2"><span className="w-2 h-2 bg-red-500 rounded-full animate-pulse"></span>Live Traffic Feed</h3>
        <div className="space-y-3 font-mono text-sm overflow-y-auto flex-1 pr-2 text-slate-700">
          {liveFeed.map((packet, index) => (
            <div key={index} className={`p-2 border rounded flex justify-between ${packet.proto === 'UDP' && packet.port === 53 ? 'bg-red-50 border-red-200 text-red-700' : 'bg-gray-50 border-gray-200'}`}>
              <span>[{packet.proto}] {packet.src} &rarr; {packet.dst}</span>
              <span className={packet.proto === 'UDP' && packet.port === 53 ? "font-bold" : "text-gray-500"}>Port: {packet.port}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

function MapView({ markers, recentAlert }) {
  const [hoveredCountry, setHoveredCountry] = useState("");
  return (
    <div className="max-w-7xl mx-auto space-y-6 animate-in fade-in duration-300">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-white p-6 rounded-xl border shadow-sm col-span-2 flex items-center justify-between">
          <div>
            <h2 className="text-2xl font-bold flex items-center gap-2"><Globe className="text-blue-500" />Globalny monitoring zagrożeń</h2>
            <p className="text-gray-500 mt-1">Wizualizacja źródeł ruchu sieciowego w czasie rzeczywistym.</p>
          </div>
        </div>
        <div className="bg-slate-900 text-white p-6 rounded-xl shadow-sm flex flex-col justify-center relative overflow-hidden">
          <ShieldAlert className="absolute right-[-20px] bottom-[-20px] text-slate-800 w-32 h-32 opacity-50" />
          <p className="text-slate-400 text-sm mb-1 z-10 font-semibold">OSTATNI ATAK</p>
          {recentAlert ? (
            <div className="z-10">
              <p className="text-xl font-bold text-red-400">{recentAlert.ip}</p>
              <p className="text-slate-300 font-mono text-sm">PROTO: {recentAlert.proto} | PORT: {recentAlert.port}</p>
            </div>
          ) : <p className="text-slate-500 italic z-10">Oczekiwanie...</p>}
        </div>
      </div>

      <div className="bg-white rounded-xl border shadow-sm overflow-hidden relative">
        <div className="w-full h-[600px] bg-slate-50 cursor-grab active:cursor-grabbing">
          <ComposableMap projectionConfig={{ scale: 150 }} className="w-full h-full">
            <ZoomableGroup center={[0, 0]} zoom={1} minZoom={1} maxZoom={8}>
              <Geographies geography={geoUrl}>
                {({ geographies }) => geographies.map((geo) => (
                  <Geography key={geo.rsmKey} geography={geo} onMouseEnter={() => setHoveredCountry(geo.properties.name)} onMouseLeave={() => setHoveredCountry("")} fill="#e2e8f0" stroke="#cbd5e1" strokeWidth={0.5} style={{ default: { outline: "none" }, hover: { fill: "#94a3b8", outline: "none" }, pressed: { outline: "none" } }} />
                ))}
              </Geographies>
              {markers.map((marker) => (
                <Marker key={marker.id} coordinates={marker.coordinates}>
                  <circle r={marker.proto === 'UDP' ? 6 : 4} fill={marker.proto === 'UDP' ? "#ef4444" : "#3b82f6"} className="animate-ping opacity-75" />
                  <circle r={marker.proto === 'UDP' ? 4 : 2} fill={marker.proto === 'UDP' ? "#991b1b" : "#1e40af"} />
                </Marker>
              ))}
            </ZoomableGroup>
          </ComposableMap>
        </div>
      </div>
    </div>
  );
}

function AlertsView({ alerts, stats, clearAlerts, onBlockIp }) {
  return (
    <div className="max-w-6xl mx-auto space-y-6 animate-in fade-in duration-300">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <SeverityCard label="Wysokie Zagrożenie" count={stats.high} color="bg-red-500" icon={<AlertCircle />} />
        <SeverityCard label="Średnie Ryzyko" count={stats.medium} color="bg-amber-500" icon={<Zap />} />
        <SeverityCard label="Informacyjne" count={stats.low} color="bg-blue-500" icon={<BrainCircuit />} />
      </div>
      <div className="bg-white p-4 rounded-xl border flex items-center justify-between">
        <button onClick={clearAlerts} className="flex items-center gap-2 px-3 py-1.5 border rounded-lg text-sm text-red-600 hover:bg-red-50"><Trash2 size={16} /> Wyczyść historię</button>
        <div className="text-sm text-gray-500">Status: <span className="text-green-600 font-bold">GPT-4-IDS ONLINE</span></div>
      </div>
      <div className="space-y-4">
        {alerts.map((alert) => (
          <div key={alert.id} className={`bg-white rounded-xl border shadow-sm overflow-hidden border-l-4 ${alert.severity === 'HIGH' ? 'border-l-red-500' : alert.severity === 'MEDIUM' ? 'border-l-amber-500' : 'border-l-blue-500'}`}>
            <div className="p-5">
              <div className="flex justify-between items-start mb-4">
                <div className="flex items-center gap-3">
                  <div className={`p-2 rounded-lg ${alert.severity === 'HIGH' ? 'bg-red-50 text-red-600' : alert.severity === 'MEDIUM' ? 'bg-amber-50 text-amber-600' : 'bg-blue-50 text-blue-600'}`}><ShieldAlert size={20} /></div>
                  <div>
                    <h3 className="font-bold text-lg">{alert.threat}</h3>
                    <p className="text-sm text-gray-500 font-mono">Źródło: {alert.src} &rarr; Cel: {alert.dst} [{alert.proto}:{alert.port}]</p>
                  </div>
                </div>
                <div className="text-right text-2xl font-black text-slate-800">{alert.confidence}%</div>
              </div>
              <div className="bg-slate-50 p-4 rounded-lg text-sm text-slate-700 border italic mb-4"><strong>Analiza LLM:</strong> {alert.analysis}</div>
              <div className="flex justify-end gap-3">
                <button
                  onClick={() => onBlockIp(alert.src)}
                  className={`px-4 py-2 text-sm font-bold text-white rounded-lg transition-colors ${alert.severity === 'HIGH' ? 'bg-red-600 hover:bg-red-700' : 'bg-slate-800 hover:bg-slate-700'}`}
                >
                  {alert.action}
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

function StatCard({ title, value, trend, icon, isAlert = false }) {
  return (
    <div className={`bg-white p-6 rounded-xl border shadow-sm flex items-start justify-between ${isAlert ? 'border-red-200 bg-red-50/30' : ''}`}>
      <div>
        <p className="text-sm text-gray-500 mb-1">{title}</p>
        <h4 className="text-2xl font-bold text-slate-800">{value}</h4>
        <span className="text-sm text-blue-500 animate-pulse">{trend}</span>
      </div>
      <div className="p-3 bg-gray-50 rounded-lg text-gray-600">{icon}</div>
    </div>
  );
}

function SeverityCard({ label, count, color, icon }) {
  return (
    <div className="bg-white p-6 rounded-xl border shadow-sm flex items-center gap-4">
      <div className={`p-3 rounded-xl text-white ${color}`}>{icon}</div>
      <div><p className="text-sm text-gray-500">{label}</p><p className="text-2xl font-bold">{count}</p></div>
    </div>
  );
}