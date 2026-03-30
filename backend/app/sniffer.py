from scapy.all import sniff, IP, TCP, UDP
import time

stats = {
    "total_packets": 0,
    "tcp_count": 0,
    "udp_count": 0,
    "unique_ips": set()
}

def process_packet(packet):
    stats["total_packets"] += 1

    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        stats["unique_ips"].add(src_ip)

        if packet.haslayer(TCP):
            stats["tcp_count"] += 1
            print(f"[TCP] {src_ip} -> {dst_ip} | Port: {packet[TCP].dport}")

        elif packet.haslayer(UDP):
            stats["udp_count"] += 1
            print(f"[UDP] {src_ip} -> {dst_ip} | Port: {packet[UDP].dport}")

    if stats["total_packets"] % 10 == 0:
        print(f"\n--- RAPORT SIECIOWY ---")
        print(f"Przechwycono: {stats['total_packets']} pakietów")
        print(f"Unikalne IP w sieci: {len(stats['unique_ips'])}")
        print(f"TCP: {stats['tcp_count']} | UDP: {stats['udp_count']}")
        print(f"-----------------------\n")

print("AI-NetSentinel Sniffer uruchomiony...")
print("Nasłuchiwanie na interfejsach systemowych (Host Mode)...")

sniff(prn=process_packet, store=0)
