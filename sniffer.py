from scapy.all import sniff, IP, TCP, UDP, DNS, DNSQR
import time
from collections import defaultdict, Counter

# Paramètres de détection
THRESHOLD = 20  # Nombre max de requêtes vers un même domaine
TIME_WINDOW = 10  # Fenêtre de temps en secondes

# Stockage des requêtes
dns_requests = defaultdict(list)
alert_counter = Counter()

# Fonction de détection d'activité suspecte
def detect_anomalies(domain, src_ip):
    current_time = time.time()
    dns_requests[domain].append(current_time)

    # Filtrer les requêtes hors de la fenêtre de temps
    dns_requests[domain] = [t for t in dns_requests[domain] if current_time - t <= TIME_WINDOW]

    if len(dns_requests[domain]) > THRESHOLD:
        alert_counter[domain] += 1
        return f"ANORMAL - {len(dns_requests[domain])} requêtes en {TIME_WINDOW}s"
    return "NORMAL"

# Fonction principale de capture
def process_packet(packet):
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):  # Filtrer les requêtes DNS
        src_ip = packet[IP].src
        domain = packet[DNSQR].qname.decode() if packet[DNSQR].qname else "Unknown"

        status = detect_anomalies(domain, src_ip)
        log_entry = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {src_ip} → DNS {domain} | Statut: {status}\n"

        with open("traffic_log.txt", "a") as log_file:
            log_file.write(log_entry)
        
        print(log_entry.strip())  # Affichage en temps réel

# Exécuter le sniffer sur une interface donnée
def start_sniffer(interface="eth0"):
    print(f"Sniffer en cours sur {interface}...")
    sniff(iface=interface, filter="udp port 53", prn=process_packet, store=False)

if __name__ == "__main__":
    start_sniffer("eth0")  # Remplace par wlan0 si besoin
