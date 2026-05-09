"use client";
import { useState, useEffect } from 'react';
import { ComposableMap, Geographies, Geography, Marker, ZoomableGroup } from "react-simple-maps";
import { Globe, ShieldAlert, Navigation, MapPin } from 'lucide-react';

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

  const firstOctet = parts[0];
  const geoData = prefixToGeo[firstOctet];

  if (geoData) {
    const offsetX = (Math.random() - 0.5) * 4;
    const offsetY = (Math.random() - 0.5) * 4;
    return [geoData.coords[0] + offsetX, geoData.coords[1] + offsetY];
  }

  return [15.0 + (Math.random() * 5), 50.0 + (Math.random() * 5)];
};

export default function GeoIpMap() {
  const [markers, setMarkers] = useState([]);
  const [recentAlert, setRecentAlert] = useState(null);
  const [hoveredCountry, setHoveredCountry] = useState("");
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

        if (data.type === 'alert') {
          const coords = resolveGeoMock(data.src);
          const newMarker = {
            id: `${data.src}-${Date.now()}`,
            ip: data.src,
            proto: data.proto,
            port: data.port,
            coordinates: coords
          };

          setRecentAlert(newMarker);
          setMarkers((prev) => [...prev, newMarker].slice(-30));
        }
      } catch (err) {
        console.error("Błąd parsowania:", err);
      }
    };

    return () => {
      eventSource.close();
    };
  }, [isMounted]);

  if (!isMounted) return <div className="min-h-screen bg-slate-50 flex items-center justify-center">Ładowanie mapy...</div>;

  return (
    <div className="max-w-7xl mx-auto space-y-6">

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-white p-6 rounded-xl border shadow-sm col-span-2 flex items-center justify-between">
          <div>
            <h2 className="text-2xl font-bold flex items-center gap-2">
              <Globe className="text-blue-500" />
              Globalny monitoring zagrożeń
            </h2>
            <p className="text-gray-500 mt-1">Wizualizacja źródeł ruchu sieciowego w czasie rzeczywistym.</p>
          </div>
          <div className="flex items-center gap-2 px-4 py-2 bg-green-50 text-green-700 rounded-lg font-medium border border-green-200">
            <span className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></span>
            Geo-Feed Aktywny
          </div>
        </div>

        <div className="bg-slate-900 text-white p-6 rounded-xl border border-slate-800 shadow-sm flex flex-col justify-center relative overflow-hidden">
          <ShieldAlert className="absolute right-[-20px] bottom-[-20px] text-slate-800 w-32 h-32 opacity-50" />
          <p className="text-slate-400 text-sm mb-1 z-10 uppercase tracking-wider font-semibold">Ostatni namierzony atak</p>
          {recentAlert ? (
            <div className="z-10">
              <p className="text-xl font-bold text-red-400">{recentAlert.ip}</p>
              <p className="text-slate-300 font-mono text-sm mt-2">
                PROTO: {recentAlert.proto} | PORT: {recentAlert.port}
              </p>
              <p className="text-slate-500 text-xs mt-1">
                Lat: {recentAlert.coordinates[1].toFixed(2)}, Lon: {recentAlert.coordinates[0].toFixed(2)}
              </p>
            </div>
          ) : (
            <p className="text-slate-500 italic z-10">Oczekiwanie na ruch...</p>
          )}
        </div>
      </div>

      <div className="bg-white rounded-xl border shadow-sm overflow-hidden relative">

        <div className="absolute top-4 left-4 z-10 bg-white/90 backdrop-blur p-3 rounded-lg border shadow-sm text-sm pointer-events-none">
          <p className="font-semibold flex items-center gap-2 mb-2">
            <Navigation size={16} className="text-blue-500" />
            Legenda
          </p>
          <div className="flex items-center gap-2 text-gray-600 mb-1">
            <span className="w-3 h-3 bg-red-500 rounded-full"></span> Atak UDP (np. DNS)
          </div>
          <div className="flex items-center gap-2 text-gray-600">
            <span className="w-3 h-3 bg-blue-500 rounded-full"></span> Ruch TCP
          </div>
          <div className="mt-2 text-xs text-gray-400 border-t pt-2">
            Scroll: Zoom | Drag: Przesuń
          </div>
        </div>

        {hoveredCountry && (
          <div className="absolute top-4 right-4 z-10 bg-slate-900 text-white px-4 py-2 rounded-lg border border-slate-700 shadow-lg text-sm font-medium flex items-center gap-2 animate-in fade-in duration-200 pointer-events-none">
            <MapPin size={16} className="text-blue-400" />
            {hoveredCountry}
          </div>
        )}

        <div className="w-full h-[600px] bg-slate-50 cursor-grab active:cursor-grabbing">
          <ComposableMap projectionConfig={{ scale: 150 }} className="w-full h-full">
            {/* 2. DODANO ZoomableGroup, obejmującą kontynenty i markery */}
            <ZoomableGroup center={[0, 0]} zoom={1} minZoom={1} maxZoom={8}>
              <Geographies geography={geoUrl}>
                {({ geographies }) =>
                  geographies.map((geo) => (
                    <Geography
                      key={geo.rsmKey}
                      geography={geo}
                      onMouseEnter={() => setHoveredCountry(geo.properties.name)}
                      onMouseLeave={() => setHoveredCountry("")}
                      fill="#e2e8f0"
                      stroke="#cbd5e1"
                      strokeWidth={0.5 / 1} // Zapobiega grubnieniu linii przy zoomie
                      style={{
                        default: { outline: "none" },
                        hover: { fill: "#94a3b8", outline: "none", transition: "all 0.2s" },
                        pressed: { outline: "none" },
                      }}
                    />
                  ))
                }
              </Geographies>

              {markers.map((marker) => {
                const isUDP = marker.proto === 'UDP';
                return (
                  <Marker key={marker.id} coordinates={marker.coordinates}>
                    <circle
                      r={isUDP ? 6 : 4}
                      fill={isUDP ? "#ef4444" : "#3b82f6"}
                      className="animate-ping origin-center opacity-75"
                    />
                    <circle
                      r={isUDP ? 4 : 2}
                      fill={isUDP ? "#991b1b" : "#1e40af"}
                    />
                  </Marker>
                );
              })}
            </ZoomableGroup>
          </ComposableMap>
        </div>
      </div>
    </div>
  );
}