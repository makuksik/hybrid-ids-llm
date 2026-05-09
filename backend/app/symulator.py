import socket
import time
import random

TARGETS = [
    "8.8.8.8", "12.34.56.78", "17.12.34.56", "24.50.60.70", 
    "50.1.2.3", "80.99.88.77", "104.20.30.40", "142.250.180.14"
]

def simulate_attack():
    print("Odpalanie symulacji ataku...")
    print("Naciśnij Ctrl+C, żeby przerwać.")
    
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    try:
        while True:
            target_ip = random.choice(TARGETS)
            attack_type = random.choice(["DNS_DDOS", "PORT_SCAN", "NORMAL"])
            
            if attack_type == "DNS_DDOS":
                # Wysyła śmieci na port 53 (UDP) - Wyzwoli CZERWONY ALERT (High)
                udp_sock.sendto(b"FAKE_DNS_PAYLOAD_TO_TRIGGER_IDS_HIGH_ALERT", (target_ip, 53))
                print(f"[HIGH] DNS DDoS na -> {target_ip}:53")
                
            elif attack_type == "PORT_SCAN":
                # Symuluje ruch TCP na niski port np. 22 (SSH) lub 80 (HTTP) - Wyzwoli ŻÓŁTY ALERT (Medium)
                # UDP w skrypcie dla szybkosci, na prezentacji mozemy ustawic regule na dport
                udp_sock.sendto(b"SYN_SCAN_SIMULATION", (target_ip, 22))
                print(f"[MEDIUM] Skanowanie portu 22 na -> {target_ip}:22")
                
            else:
                # Zwykły ruch na wysokie porty - Wyzwoli NIEBIESKI ALERT (Low)
                high_port = random.randint(10000, 60000)
                udp_sock.sendto(b"NORMAL_TRAFFIC", (target_ip, high_port))
                print(f"[LOW] Zwykły ruch do -> {target_ip}:{high_port}")
            
            # Prędkość strzelania pakietami (0.1 sekundy = 10 pakietów na sekundę)
            time.sleep(0.1)

    except KeyboardInterrupt:
        print("\nSymulacja zatrzymana.")
        udp_sock.close()

if __name__ == "__main__":
    simulate_attack()