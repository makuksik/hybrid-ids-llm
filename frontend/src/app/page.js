"use client";
import { useState, useEffect } from 'react';
import { ArrowUpRight, ArrowDownRight, Activity, AlertTriangle, Globe } from 'lucide-react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, Legend } from 'recharts';

export default function Dashboard() {
  const [stats, setStats] = useState({ total: 0, tcp: 0, udp: 0, uniqueIps: 0 });
  const [liveFeed, setLiveFeed] = useState([]);
  const [dataPPS, setDataPPS] = useState([]);
  const [isMounted, setIsMounted] = useState(false);

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
          setStats({
            total: data.total,
            tcp: data.tcp,
            udp: data.udp,
            uniqueIps: data.unique_ips
          });

          setDataPPS((prev) => {
            const newPoint = { 
              time: new Date().toLocaleTimeString('pl-PL', { minute: '2-digit', second: '2-digit' }), 
              pps: data.pps || data.total 
            };
            return [...prev, newPoint].slice(-15);
          });
        } else if (data.type === 'alert') {
          setLiveFeed((prevFeed) => {
            const newFeed = [data, ...prevFeed];
            return newFeed.slice(0, 15);
          });
        }
      } catch (err) {
        console.error("Błąd parsowania:", err);
      }
    };

    eventSource.onerror = (error) => {
      eventSource.close();
    };

    return () => {
      eventSource.close();
    };
  }, [isMounted]);

  if (!isMounted) return <div className="min-h-screen bg-slate-50 flex items-center justify-center">Ładowanie interfejsu...</div>;

  const dataProto = stats.total === 0 
    ? [{ name: 'Brak ruchu', value: 1, color: '#e2e8f0' }]
    : [
        { name: 'TCP', value: stats.tcp, color: '#3b82f6' },
        { name: 'UDP', value: stats.udp, color: '#a855f7' },
        { name: 'Inne', value: Math.max(0, stats.total - stats.tcp - stats.udp), color: '#94a3b8' }
      ];

  return (
    <div className="max-w-7xl mx-auto space-y-6 p-6">
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <StatCard title="Suma Pakietów" value={stats.total.toLocaleString()} trend="Live" icon={<Activity />} />
        <StatCard title="Ruch TCP" value={stats.tcp.toLocaleString()} trend="Live" icon={<ArrowUpRight className="text-green-500" />} />
        <StatCard title="Ruch UDP" value={stats.udp.toLocaleString()} trend="Live" icon={<ArrowDownRight className="text-blue-500" />} />
        <StatCard title="Unikalne IP" value={stats.uniqueIps.toLocaleString()} trend="Live" icon={<Globe />} isAlert={true} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="bg-white p-6 rounded-xl border shadow-sm col-span-2 h-96 flex flex-col">
          <h3 className="text-lg font-semibold mb-4">Natężenie ruchu (Packets Per Second)</h3>
          <div style={{ height: '300px', width: '100%' }}>
            <ResponsiveContainer width="100%" height={300}>
              <LineChart data={dataPPS}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#f1f5f9" />
                <XAxis dataKey="time" tick={{fontSize: 12}} />
                <YAxis hide />
                <Tooltip />
                <Line type="monotone" dataKey="pps" stroke="#3b82f6" strokeWidth={3} dot={false} isAnimationActive={false} />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="bg-white p-6 rounded-xl border shadow-sm h-96 flex flex-col">
          <h3 className="text-lg font-semibold mb-4">Podział Protokołów</h3>
          <div style={{ height: '300px', width: '100%' }}>
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie data={dataProto} innerRadius={60} outerRadius={80} paddingAngle={5} dataKey="value" isAnimationActive={false}>
                  {dataProto.map((entry, index) => <Cell key={`cell-${index}`} fill={entry.color} />)}
                </Pie>
                <Tooltip />
                <Legend verticalAlign="bottom" height={36} iconType="circle" />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white p-6 rounded-xl border shadow-sm flex flex-col h-96">
          <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <span className="w-2 h-2 bg-red-500 rounded-full animate-pulse"></span>
            Live Traffic Feed
          </h3>
          <div className="space-y-3 font-mono text-sm overflow-y-auto flex-1 pr-2">
            {liveFeed.length === 0 ? (
              <p className="text-gray-400 text-center mt-10">Oczekiwanie na pakiety...</p>
            ) : (
              liveFeed.map((packet, index) => (
                <div key={index} className={`p-2 border rounded flex justify-between ${packet.proto === 'UDP' && packet.port === 53 ? 'bg-red-50 border-red-200 text-red-700' : 'bg-gray-50 border-gray-200'}`}>
                  <span>[{packet.proto}] {packet.src} &rarr; {packet.dst}</span>
                  <span className={packet.proto === 'UDP' && packet.port === 53 ? "font-bold" : "text-gray-500"}>
                    Port: {packet.port}
                  </span>
                </div>
              ))
            )}
          </div>
        </div>

        <div className="bg-white p-6 rounded-xl border shadow-sm border-l-4 border-l-purple-500 h-96 flex flex-col">
          <div className="flex items-center gap-2 mb-4">
            <AlertTriangle className="text-purple-500" />
            <h3 className="text-lg font-semibold">Ostatnia analiza LLM</h3>
          </div>
          <div className="bg-purple-50 text-purple-900 p-4 rounded-lg text-sm leading-relaxed flex-1 overflow-auto">
            <strong>Analiza anomalii #4092:</strong> Wykryto nietypowy wzrost zapytań UDP na porcie 53 (DNS) z pojedynczego adresu IP. LLM klasyfikuje to zdarzenie jako potencjalną próbę <em>DNS Amplification DDoS</em> (Pewność: 87%). <br/><br/>
            <strong>Sugerowana akcja:</strong> Uruchomienie skryptu blokującego IP (Firewall script).
          </div>
          <button className="mt-4 w-full bg-slate-900 text-white py-2 rounded-lg hover:bg-slate-800 transition-colors">
            Zablokuj IP (Active Response)
          </button>
        </div>
      </div>
    </div>
  );
}

function StatCard({ title, value, trend, icon, isAlert = false }) {
  return (
    <div className={`bg-white p-6 rounded-xl border shadow-sm flex items-start justify-between ${isAlert ? 'border-red-200 bg-red-50/30' : ''}`}>
      <div>
        <p className="text-sm text-gray-500 mb-1">{title}</p>
        <h4 className="text-2xl font-bold">{value}</h4>
        <span className={`text-sm ${trend === 'Live' ? 'text-blue-500 animate-pulse' : (trend.startsWith('+') ? 'text-green-500' : 'text-red-500')}`}>
          {trend}
        </span>
      </div>
      <div className="p-3 bg-gray-50 rounded-lg text-gray-600">
        {icon}
      </div>
    </div>
  )
}