from scapy.all import sniff, IP, TCP, UDP

stats = {
    "total_packets": 0,
    "tcp_count": 0,
    "udp_count": 0,
    "unique_ips": set()
}

def process_packet(packet, callback):
    global stats
    stats["total_packets"] += 1

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        stats["unique_ips"].add(src_ip)

        alert = None
        if packet.haslayer(TCP):
            stats["tcp_count"] += 1
            alert = {"type": "alert", "proto": "TCP", "src": src_ip, "dst": dst_ip, "port": packet[TCP].dport}
        elif packet.haslayer(UDP):
            stats["udp_count"] += 1
            alert = {"type": "alert", "proto": "UDP", "src": src_ip, "dst": dst_ip, "port": packet[UDP].dport}

        if alert:
            callback(alert)

    if stats["total_packets"] % 10 == 0:
        report = {
            "type": "report",
            "total": stats["total_packets"],
            "unique_ips": len(stats["unique_ips"]),
            "tcp": stats["tcp_count"],
            "udp": stats["udp_count"]
        }
        callback(report)

def start_sniffer(callback):
    sniff(prn=lambda pkt: process_packet(pkt, callback), store=0)
