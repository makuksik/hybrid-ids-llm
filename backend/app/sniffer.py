import time 
import random
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
    print("Sniffer w trybie SYMULATORA")
    
    base_rate = 50 
    
    while True:
        current_rate = int(base_rate + random.uniform(-20, 100))
        sleep_time = 1.0 / max(1, current_rate)
        
        is_tcp = random.random() > 0.3 
        proto = "TCP" if is_tcp else "UDP"
        
        public_octets = [8, 12, 17, 24, 45, 50, 72, 80, 104, 142, 185, 200, 212]
        
        src_ip = f"{random.choice(public_octets)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 254)}"
        
        dst_ip = "185.12.5.55"

        port = random.randint(1024, 65535) if is_tcp else 53
        
        alert = {"type": "alert", "proto": proto, "src": src_ip, "dst": dst_ip, "port": port}
        
        class FakePacket:
            def haslayer(self, layer):
                if layer == IP: return True
                if layer == TCP: return is_tcp
                if layer == UDP: return not is_tcp
                return False
            def __getitem__(self, layer):
                class FakeLayer: pass
                fake = FakeLayer()
                fake.src = src_ip
                fake.dst = dst_ip
                fake.dport = port
                return fake
                
        process_packet(FakePacket(), callback)
        
        time.sleep(sleep_time)