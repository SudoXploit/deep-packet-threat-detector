from scapy.all import sniff, Raw, TCP, IP

def detect_http_creds(pkt):
    if pkt.haslayer(Raw):
        payload = pkt[Raw].load.decode(errors='ignore')
        if "POST" in payload and ("username" in payload or "password" in payload):
            print(f"\n[+] Potential Credential Leak: {pkt[IP].src} -> {pkt[IP].dst}")
            print(payload)

sniff(filter="tcp port 80", prn=detect_http_creds, store=False)
