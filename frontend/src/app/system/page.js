"use client";
import { useState, useEffect } from 'react';
import {
  Server, Settings, Play, Square, RefreshCcw,
  ShieldCheck, Cpu, HardDrive, Activity, Save,
  FileText, Terminal
} from 'lucide-react';

export default function SystemManagement() {
  const [isSnifferActive, setIsSnifferActive] = useState(true);
  const [logs, setLogs] = useState([
    { id: 1, time: "12:45:10", msg: "System IDS zainicjalizowany", type: "info" },
    { id: 2, time: "12:45:12", msg: "Moduł LLM (GPT-4) połączony", type: "success" },
    { id: 3, time: "12:46:01", msg: "Sniffer: Nasłuchiwanie na interfejsie eth0...", type: "info" },
    { id: 4, time: "13:10:05", msg: "Wykryto próbę skanowania portów - Alert wysłany do UI", type: "warning" },
  ]);

  const toggleSniffer = () => {
    const action = isSnifferActive ? "zatrzymany" : "uruchomiony";
    setIsSnifferActive(!isSnifferActive);
    addLog(`Sniffer został ${action} ręcznie przez administratora`, isSnifferActive ? "warning" : "success");
  };

  const addLog = (msg, type = "info") => {
    const newLog = {
      id: Date.now(),
      time: new Date().toLocaleTimeString(),
      msg,
      type
    };
    setLogs(prev => [newLog, ...prev].slice(0, 10));
  };

  return (
    <div className="max-w-6xl mx-auto space-y-6">
      {/* Nagłówek statusu */}
      <div className="flex items-center justify-between bg-white p-6 rounded-xl border shadow-sm">
        <div className="flex items-center gap-4">
          <div className={`p-3 rounded-full ${isSnifferActive ? 'bg-green-100 text-green-600' : 'bg-red-100 text-red-600'}`}>
            <Server size={32} />
          </div>
          <div>
            <h2 className="text-2xl font-bold">Zarządzanie Systemem IDS</h2>
            <p className="text-gray-500">Zarządzaj procesami, konfiguracją i monitoruj stan infrastruktury.</p>
          </div>
        </div>
        <div className="flex gap-3">
          <button
            onClick={toggleSniffer}
            className={`flex items-center gap-2 px-6 py-2.5 rounded-lg font-bold transition-all ${
              isSnifferActive
              ? 'bg-red-600 hover:bg-red-700 text-white'
              : 'bg-green-600 hover:bg-green-700 text-white'
            }`}
          >
            {isSnifferActive ? <><Square size={18} /> Zatrzymaj IDS</> : <><Play size={18} /> Uruchom IDS</>}
          </button>
          <button className="p-2.5 border rounded-lg hover:bg-gray-50 text-gray-600">
            <RefreshCcw size={20} />
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Parametry systemowe */}
        <div className="lg:col-span-2 space-y-6">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <StatusMetric label="Użycie CPU" value="12%" icon={<Cpu size={18} />} progress={12} />
            <StatusMetric label="Użycie RAM" value="1.2 GB / 4 GB" icon={<HardDrive size={18} />} progress={30} />
            <StatusMetric label="Uptime" value="14d 2h 15m" icon={<Activity size={18} />} progress={100} color="bg-blue-500" />
          </div>

          {/* Konfiguracja */}
          <div className="bg-white rounded-xl border shadow-sm overflow-hidden">
            <div className="p-4 border-b bg-gray-50 flex items-center gap-2 font-bold">
              <Settings size={18} /> Konfiguracja Sniffera
            </div>
            <div className="p-6 space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <label className="text-sm font-medium text-gray-700">Interfejs Sieciowy</label>
                  <select className="w-full border rounded-lg p-2 text-sm">
                    <option>eth0 (172.18.0.3)</option>
                    <option>wlan0</option>
                    <option>lo (loopback)</option>
                  </select>
                </div>
                <div className="space-y-2">
                  <label className="text-sm font-medium text-gray-700">Czułość LLM (Threshold)</label>
                  <input type="range" className="w-full" min="0" max="100" />
                </div>
              </div>
              <div className="flex items-center gap-3 p-3 bg-blue-50 rounded-lg text-blue-800 text-sm">
                <ShieldCheck size={18} />
                System automatycznie aktualizuje bazę sygnatur co 24 godziny.
              </div>
              <button className="flex items-center gap-2 bg-slate-900 text-white px-4 py-2 rounded-lg text-sm font-medium hover:bg-slate-800 transition-colors">
                <Save size={16} /> Zapisz zmiany
              </button>
            </div>
          </div>
        </div>

        {/* Logi systemowe */}
        <div className="bg-slate-900 rounded-xl shadow-lg border border-slate-800 flex flex-col h-full min-h-[400px]">
          <div className="p-4 border-b border-slate-800 flex items-center justify-between">
            <div className="flex items-center gap-2 text-white font-bold">
              <Terminal size={18} className="text-green-400" />
              <span>Logi Systemowe</span>
            </div>
            <FileText size={16} className="text-slate-500" />
          </div>
          <div className="p-4 font-mono text-xs space-y-3 overflow-y-auto flex-1">
            {logs.map(log => (
              <div key={log.id} className="flex gap-3">
                <span className="text-slate-500">[{log.time}]</span>
                <span className={
                  log.type === 'warning' ? 'text-amber-400' :
                  log.type === 'success' ? 'text-green-400' : 'text-blue-300'
                }>
                  {log.msg}
                </span>
              </div>
            ))}
            <div className="text-green-500 animate-pulse">_</div>
          </div>
        </div>
      </div>
    </div>
  );
}

function StatusMetric({ label, value, icon, progress, color = "bg-green-500" }) {
  return (
    <div className="bg-white p-4 rounded-xl border shadow-sm">
      <div className="flex items-center gap-2 text-gray-500 text-sm mb-2">
        {icon} {label}
      </div>
      <div className="text-xl font-bold mb-3">{value}</div>
      <div className="w-full bg-gray-100 rounded-full h-1.5">
        <div className={`h-1.5 rounded-full ${color}`} style={{ width: `${progress}%` }}></div>
      </div>
    </div>
  );
}