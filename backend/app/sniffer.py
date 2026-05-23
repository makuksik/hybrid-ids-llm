import time
import sqlite3
import threading
import queue
import json
import os
from dotenv import load_dotenv

load_dotenv()

import google.generativeai as genai
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP

genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
model = genai.GenerativeModel('gemini-3.1-flash-lite-preview')

stats = {
    "total_packets": 0,
    "tcp_count": 0,
    "udp_count": 0,
    "unique_ips": set()
}

last_report_time = time.time()
current_second_packets = 0

ai_queue = queue.Queue()


def init_db():
    conn = sqlite3.connect("net_sentinel.db")
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            proto TEXT,
            src_ip TEXT,
            dst_ip TEXT,
            port INTEGER,
            severity TEXT,
            threat TEXT,
            analysis TEXT,
            confidence INTEGER,
            action TEXT
        )
    ''')
    conn.commit()
    conn.close()


init_db()


def analyze_with_gemini(alert):
    prompt = f"""
    Jesteś zaawansowanym modułem analitycznym systemu IDS. Przeanalizuj poniższy pakiet sieciowy i zwróć WYŁĄCZNIE czysty JSON (bez bloków markdown ```json).

    Wymagane klucze JSON:
    - "severity": "HIGH", "MEDIUM" lub "LOW"
    - "threat": krótka kategoria zagrożenia (np. "DDoS Amplification", "Skanowanie portów", "Zwykły ruch")
    - "analysis": jedno zwięzłe zdanie z analitycznym wyjaśnieniem sytuacji po polsku
    - "confidence": liczba z przedziału od 0 do 100 określająca pewność detekcji
    - "action": sugerowana reakcja systemu ("Zablokuj IP w Firewallu", "Obserwuj hosta", "Zignoruj")

    Dane wejściowe pakietu:
    - Protokół: {alert['proto']}
    - Port docelowy: {alert['port']}
    - IP źródłowe: {alert['src']}
    - IP docelowe: {alert['dst']}
    """

    try:
        response = model.generate_content(prompt)
        response_text = response.text.strip()

        if response_text.startswith("```json"):
            response_text = response_text[7:-3]
        elif response_text.startswith("```"):
            response_text = response_text[3:-3]

        ai_data = json.loads(response_text)

        alert.update(ai_data)
        alert["id"] = f"{time.time()}-{alert['src']}"
        return alert

    except Exception as e:
        print(f"[!] Błąd analizy Gemini API: {e}")
        alert.update({
            "id": f"{time.time()}-{alert['src']}",
            "severity": "LOW",
            "threat": "Błąd klasyfikatora AI",
            "analysis": "Klasyfikacja LLM niedostępna. Wymagana manualna weryfikacja logów.",
            "confidence": 0,
            "action": "Obserwuj hosta"
        })
        return alert


def save_alert(alert):
    current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = sqlite3.connect("net_sentinel.db")
    cursor = conn.cursor()
    cursor.execute(
        """INSERT INTO alerts 
           (timestamp, proto, src_ip, dst_ip, port, severity, threat, analysis, confidence, action) 
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (current_time, alert["proto"], alert["src"], alert["dst"], alert["port"],
         alert.get("severity", "LOW"), alert.get("threat", ""),
         alert.get("analysis", ""), alert.get("confidence", 0), alert.get("action", ""))
    )
    conn.commit()
    conn.close()

    with open("alerts_log.txt", "a", encoding="utf-8") as f:
        f.write(
            f"[{current_time}] [{alert.get('severity')}] {alert['proto']} {alert['src']}->{alert['dst']}:{alert['port']} | Zagrożenie: {alert.get('threat')}\n")


def ai_worker(callback):
    while True:
        raw_alert = ai_queue.get()
        enriched_alert = analyze_with_gemini(raw_alert)
        save_alert(enriched_alert)
        callback(enriched_alert)
        ai_queue.task_done()

        time.sleep(5)


def process_packet(packet, callback):
    global stats, last_report_time, current_second_packets

    stats["total_packets"] += 1
    current_second_packets += 1

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        stats["unique_ips"].add(src_ip)
        stats["unique_ips"].add(dst_ip)

        alert = None
        if packet.haslayer(TCP):
            stats["tcp_count"] += 1
            alert = {"type": "alert", "proto": "TCP", "src": src_ip, "dst": dst_ip, "port": packet[TCP].dport}
        elif packet.haslayer(UDP):
            stats["udp_count"] += 1
            alert = {"type": "alert", "proto": "UDP", "src": src_ip, "dst": dst_ip, "port": packet[UDP].dport}

        if alert and stats["total_packets"] % 50 == 0:
            ai_queue.put(alert)

    current_time = time.time()
    if current_time - last_report_time >= 1.0:
        report = {
            "type": "report",
            "total": stats["total_packets"],
            "pps": current_second_packets,
            "unique_ips": len(stats["unique_ips"]),
            "tcp": stats["tcp_count"],
            "udp": stats["udp_count"]
        }
        callback(report)
        current_second_packets = 0
        last_report_time = current_time


def start_sniffer(callback):
    worker = threading.Thread(target=ai_worker, args=(callback,), daemon=True)
    worker.start()

    sniff(prn=lambda pkt: process_packet(pkt, callback), store=0)