import time # DODANE
from scapy.all import sniff, IP, TCP, UDP

stats = {
    "total_packets": 0,
    "tcp_count": 0,
    "udp_count": 0,
    "unique_ips": set()
}

last_report_time = time.time()
current_second_packets = 0 

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
            callback(alert)

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
    sniff(prn=lambda pkt: process_packet(pkt, callback), store=0)